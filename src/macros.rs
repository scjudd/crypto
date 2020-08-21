macro_rules! copy_from_slice {
    ($zero:expr, $slice:expr) => {{
        let mut ret = $zero;
        ret.copy_from_slice($slice);
        ret
    }};
}
