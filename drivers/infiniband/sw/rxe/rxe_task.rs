// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Scheduling and draining the requester, responder and completer tasks.

#![forbid(unsafe_code)]

use crate::{
    rxe_param as params,
    rxe_task_ffi::{
        self,
        Execution, //
    }, //
};
use kernel::{
    prelude::*,
    sync::{
        CondVar,
        SpinLockIrq, //
    },
    workqueue::{
        self,
        Work,
        WorkItem, //
    }, //
};

/// Scheduling policy, exclusively accessed through the task lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum State {
    Idle,
    Busy,
    Armed,
    Draining,
    Drained,
    Invalid,
}

/// Action after exhausting one batch of transport work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Continue,
    Stop,
    Reschedule,
}

/// State and accounting for one work item; it contains no kernel pointers.
pub(crate) struct Scheduler {
    state: State,
    scheduled: c_long,
    completed: c_long,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Idle,
            scheduled: 0,
            completed: 0,
        }
    }

    /// Returns true only when the idle task needs a new workqueue reservation.
    pub(crate) fn reserve(&mut self) -> bool {
        match self.state {
            State::Idle => {
                self.state = State::Busy;
                self.scheduled = self.scheduled.wrapping_add(1);
                true
            }
            State::Busy => {
                self.state = State::Armed;
                false
            }
            _ => false,
        }
    }

    /// Retires a reservation cancelled before the worker began.
    pub(crate) fn begin(&mut self) -> bool {
        if self.state >= State::Drained {
            self.complete();
            false
        } else {
            true
        }
    }

    /// Chooses whether to continue, stop or yield after a batch.
    pub(crate) fn after_run(&mut self, progress: bool) -> Action {
        let action = if self.state == State::Draining {
            self.state = State::Drained;
            Action::Stop
        } else if progress {
            self.state = State::Idle;
            Action::Reschedule
        } else {
            match self.state {
                State::Busy => {
                    self.state = State::Idle;
                    Action::Stop
                }
                State::Armed => {
                    self.state = State::Busy;
                    Action::Continue
                }
                State::Draining => {
                    self.state = State::Drained;
                    Action::Stop
                }
                _ => {
                    kernel::warn_on!(true);
                    pr_debug!("unexpected task state = {:?}\n", self.state);
                    self.state = State::Idle;
                    Action::Stop
                }
            }
        };
        if action != Action::Continue {
            self.complete();
        }
        action
    }

    fn complete(&mut self) {
        self.completed = self.completed.wrapping_add(1);
        if kernel::warn_on!(self.completed != self.scheduled) {
            pr_debug!(
                "{} tasks scheduled, {} tasks done\n",
                self.scheduled,
                self.completed
            );
        }
    }

    pub(crate) fn done(&self, pending: bool) -> bool {
        !pending && matches!(self.state, State::Idle | State::Drained)
    }

    /// Stops accepting reservations and returns whether the worker must drain.
    pub(crate) fn start_drain(&mut self, pending: bool, final_state: State) -> bool {
        if !self.done(pending) && self.state < State::Drained {
            self.state = State::Draining;
            true
        } else {
            self.finish_drain(final_state);
            false
        }
    }

    pub(crate) fn finish_drain(&mut self, final_state: State) {
        self.state = final_state;
    }

    pub(crate) fn enable(&mut self) {
        if self.state != State::Invalid {
            self.state = State::Idle;
        }
    }
}

/// Exclusive execution authority, consumed before publishing scheduler completion.
///
/// Only the work callback can construct this value after successful admission. Keeping the
/// execution private prevents callers from replacing its identity while authority is active.
pub(super) struct Runner {
    execution: Execution,
}

impl Runner {
    pub(super) fn execution(&self) -> &Execution {
        &self.execution
    }
}

#[pin_data]
struct Invocation {
    #[pin]
    work: Work<Self>,
    execution: Option<Execution>,
}

workqueue::impl_has_work! {
    impl HasWork<Self> for Invocation { self.work }
}

struct Slot {
    scheduler: Scheduler,
    work: Option<Pin<KBox<Invocation>>>,
}

impl Slot {
    fn schedule(&mut self, execution: &Execution) {
        if !self.scheduler.reserve() {
            return;
        }
        let mut work = self.work.take().expect("idle task owns its work item");
        *work.as_mut().project().execution = Some(execution.clone());
        // Exclusive box ownership prevents duplicate queueing. Scheduling and handing the
        // invocation to the worker occur under the same lock as scheduler reservation.
        execution.queue().enqueue(work);
    }

    fn pending(&self) -> bool {
        self.work.is_none()
    }
}

/// Owns a preallocated invocation whenever it is not queued or executing.
///
/// Scheduling transfers its unique pinned box to the workqueue and acquires a QP reference.
/// The worker returns the box before notifying drainers. No scheduling path allocates memory.
#[pin_data]
pub(super) struct Runtime {
    #[pin]
    state: SpinLockIrq<Slot>,
    #[pin]
    done: CondVar,
}

impl Runtime {
    pub(super) fn new() -> Result<impl PinInit<Self, Error>> {
        let work = KBox::pin_init(
            pin_init!(Invocation {
                work <- workqueue::new_work!("rxe_task"),
                execution: None,
            }),
            GFP_KERNEL,
        )?;
        Ok(try_pin_init!(Self {
            state <- kernel::new_spinlock_irq!(Slot {
                scheduler: Scheduler::new(),
                work: Some(work),
            }),
            done <- kernel::new_condvar!("rxe_task_done"),
        }))
    }

    pub(super) fn schedule(&self, execution: &Execution) {
        // A runtime may only dispatch its own QP's execution binding. This also keeps the
        // preallocated work slot and callback's return destination identical in safe callers.
        assert!(core::ptr::eq(self, execution.runtime()));
        self.state.lock().schedule(execution);
    }

    /// Stops new reservations and sleeps until the invocation has returned its work box.
    pub(super) fn drain(&self, final_state: State) {
        let mut state = self.state.lock();
        let pending = state.pending();
        if !state.scheduler.start_drain(pending, final_state) {
            return;
        }
        while !state.scheduler.done(state.pending()) {
            self.done.wait(&mut state);
        }
        state.scheduler.finish_drain(final_state);
    }

    pub(super) fn enable(&self) {
        self.state.lock().scheduler.enable();
    }
}

impl WorkItem for Invocation {
    type Pointer = Pin<KBox<Self>>;

    fn run(mut this: Self::Pointer) {
        let execution = this.as_mut().project().execution.take().unwrap();
        {
            let mut state = execution.runtime().state.lock();
            if !state.scheduler.begin() {
                state.work = Some(this);
                drop(state);
                execution.runtime().done.notify_all();
                return;
            }
        }
        let mut runner = Runner { execution };
        loop {
            let mut result = 0;
            // The transport's original do/while permits MAX_ITERATIONS + 1 calls.
            for _ in 0..=params::RXE_MAX_ITERATIONS {
                result = rxe_task_ffi::step(&mut runner);
                if result != 0 {
                    break;
                }
            }
            // Consume authority before making completion visible. Only Continue can create
            // another Runner; drainers may release transport resources after other outcomes.
            let Runner { execution } = runner;
            let mut state = execution.runtime().state.lock();
            let action = state.scheduler.after_run(result == 0);
            if action == Action::Continue {
                drop(state);
                runner = Runner { execution };
                continue;
            }
            state.work = Some(this);
            if action == Action::Reschedule {
                state.schedule(&execution);
            }
            drop(state);
            execution.runtime().done.notify_all();
            // Event handlers follow the RDMA callback contract and must not sleep.
            // In particular, they must defer QP query/modify to another execution
            // context: a requeued invocation may still need this native work item.
            execution.dispatch_events();
            // No task or transport access follows release of this invocation's QP reference.
            return;
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_scheduler)]
mod tests {
    use super::*;

    #[test]
    fn rearm_and_reschedule() {
        let mut task = Scheduler::new();
        assert!(task.reserve());
        assert!(task.begin());
        assert!(!task.reserve());
        assert!(!task.reserve());
        assert_eq!(task.after_run(false), Action::Continue);
        assert_eq!(task.after_run(true), Action::Reschedule);
        assert!(task.done(false));
        assert!(task.reserve());
        assert_eq!(task.after_run(false), Action::Stop);
        assert_eq!(task.scheduled, 2);
        assert_eq!(task.completed, 2);
    }

    #[test]
    fn drain_active_worker() {
        let mut task = Scheduler::new();
        assert!(task.reserve());
        assert!(task.start_drain(true, State::Drained));
        assert!(!task.reserve());
        assert!(task.begin());
        // A continuously publishing client must not keep a control operation waiting.
        assert_eq!(task.after_run(true), Action::Stop);
        assert!(task.done(false));
        task.finish_drain(State::Drained);
        assert!(!task.reserve());
        task.enable();
        assert!(task.reserve());
        assert_eq!(task.after_run(false), Action::Stop);
        assert!(!task.start_drain(false, State::Invalid));
        task.enable();
        assert!(!task.reserve());
        assert_eq!(task.scheduled, task.completed);
    }

    #[test]
    fn disable_between_completion_and_reschedule() {
        let mut task = Scheduler::new();
        assert!(task.reserve());
        assert_eq!(task.after_run(true), Action::Reschedule);
        assert!(!task.start_drain(false, State::Drained));
        assert!(!task.reserve());
        assert_eq!(task.scheduled, task.completed);
        task.enable();
        assert!(task.reserve());
        assert_eq!(task.after_run(false), Action::Stop);
    }
}
