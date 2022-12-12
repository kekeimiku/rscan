use core::cmp::PartialEq;

pub fn contains<T: PartialEq>(haystack: &[T], needle: &[T]) -> bool {
    let window_size = needle.len();
    if window_size == 0 {
        return true;
    }
    haystack
        .windows(window_size)
        .position(|slice| slice == needle)
        .is_some()
}
