//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.


use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::{BinaryHeap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

pub struct TaskManager {
    ready_queue: BinaryHeap<Arc<TaskControlBlock>>,
}

// YOUR JOB: FIFO->Stride
/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: BinaryHeap::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        let task = self.ready_queue.pop();
        // self.ready_queue.pop_front()
        if let Some(task) = task {
            task.step();
            Some(task)
        } else {
            None
        }
    }
    //     if let Some((idx, task_to_run)) = self.ready_queue.iter().enumerate().min_by_key(|t| t.1.inner_exclusive_access().pass) {
    //
    //         let mut inner = task_to_run.inner_exclusive_access();
    //         let t = inner.stride;
    //
    //         // println!("pid={} stride={} pass={}  total = {}", task_to_run.pid.0, t, inner.stride_pass.0, self.ready_queue.len());
    //
    //         inner.pass.step(t);
    //
    //         drop(inner);
    //         self.ready_queue.remove(idx)
    //     } else {
    //         None
    //     }
    // }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.exclusive_access().fetch()
}
