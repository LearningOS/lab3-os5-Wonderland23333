//! Implementation of process management mechanism
//!
//! Here is the entry for process scheduling required by other modules
//! (such as syscall or clock interrupt).
//! By suspending or exiting the current process, you can
//! modify the process state, manage the process queue through TASK_MANAGER,
//! and switch the control flow through PROCESSOR.
//!
//! Be careful when you see [`__switch`]. Control flow around this function
//! might not be what you expect.

mod context;
mod manager;
mod pid;
mod processor;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::loader::get_app_data_by_name;
use alloc::sync::Arc;
use lazy_static::*;
use manager::fetch_task;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};
pub use crate::mm::{VirtAddr,VirtPageNum,MapPermission,VPNRange};
use crate::config::PAGE_SIZE;

pub use context::TaskContext;
pub use manager::{add_task};
pub use pid::{pid_alloc, KernelStack, PidHandle};
pub use processor::{
    current_task, current_trap_cx, current_user_token, run_tasks, schedule, take_current_task, get_current_taskinfo,
};

/// Make current task suspended and switch to the next task
pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- release current PCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

/// Exit current task, recycle process resources and switch to the next task
pub fn exit_current_and_run_next(exit_code: i32) {
    // take from Processor
    let task = take_current_task().unwrap();
    // **** access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    // Change status to Zombie
    inner.task_status = TaskStatus::Zombie;
    // Record exit code
    inner.exit_code = exit_code;
    // do not move to its parent but under initproc

    // ++++++ access initproc TCB exclusively
    {
        let mut initproc_inner = INITPROC.inner_exclusive_access();
        for child in inner.children.iter() {
            child.inner_exclusive_access().parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }
    // ++++++ release parent PCB

    inner.children.clear();
    // deallocate user space
    inner.memory_set.recycle_data_pages();
    drop(inner);
    // **** release current PCB
    // drop task manually to maintain rc correctly
    drop(task);
    // we do not have to save task context
    let mut _unused = TaskContext::zero_init();
    schedule(&mut _unused as *mut _);
}

pub fn call_map(start: usize, len: usize, port: usize) -> isize {
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }
    if port == 0 || port > 7usize  {
        return -1;
    }
    let task = take_current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let memory_set = &mut inner.memory_set;
    let v1 = VirtPageNum::from(VirtAddr(start));
    let v2 = VirtPageNum::from(VirtAddr(start + len).ceil());
    for vpn in  v1.0 .. v2.0 {
        if let Some(m) = memory_set.translate(VirtPageNum(vpn)) {
            if m.is_valid() {
                return -1;
            }
        }
    }
    let permission = MapPermission::from_bits((port as u8) << 1).unwrap() | MapPermission::U;
    memory_set.insert_framed_area(VirtAddr(start), VirtAddr(start+len), permission);
    0
}

pub fn drop_munmap(start: usize, len: usize) -> isize{
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }
    let v1 = VirtPageNum::from(VirtAddr(start));
    let v2 = VirtPageNum::from(VirtAddr(start + len).ceil());
    let task = take_current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let memory_set = &mut inner.memory_set;
    for vpn in v1.0 .. v2.0 {
        if let Some(m) = memory_set.translate(VirtPageNum(vpn)) {
            if !m.is_valid() {
                return -1;
            }
        }
    }
    let bound = VPNRange::new(v1, v2);
    memory_set.munmap(bound);
    0
}
lazy_static! {
    /// Creation of initial process
    ///
    /// the name "initproc" may be changed to any other app name like "usertests",
    /// but we have user_shell, so we don't need to change it.
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new(TaskControlBlock::new(
        get_app_data_by_name("ch5b_initproc").unwrap()
    ));
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
}
