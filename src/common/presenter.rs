pub trait Presenter<T, U> {
    fn success(&mut self, data: T);
    fn error(&mut self, error: U);
}
