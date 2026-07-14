pub const TimeFn = *const fn () u32;

var time_fn: TimeFn = undefined;

pub fn millis() u32 {
    return time_fn();
}

pub fn set(fn_ptr: TimeFn) void {
    time_fn = fn_ptr;
}
