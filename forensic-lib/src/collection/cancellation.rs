/// The native adapter supplies signal state; the common layer does not install handlers.
pub trait Cancellation {
    fn cancelled(&self) -> bool;
}
impl Cancellation for bool {
    fn cancelled(&self) -> bool {
        *self
    }
}
