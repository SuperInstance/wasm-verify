//! A small sample wasm library for testing wasm-verify.

/// Add two i32 numbers.
#[no_mangle]
pub extern "C" fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// Compute factorial iteratively.
#[no_mangle]
pub extern "C" fn factorial(n: i32) -> i32 {
    let mut result = 1i32;
    let mut i = 2i32;
    while i <= n {
        result *= i;
        i += 1;
    }
    result
}

/// Check if a number is prime.
#[no_mangle]
pub extern "C" fn is_prime(n: i32) -> i32 {
    if n <= 1 {
        return 0;
    }
    if n <= 3 {
        return 1;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return 0;
    }
    let mut i = 5i32;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return 0;
        }
        i += 6;
    }
    1
}

/// Fibonacci number.
#[no_mangle]
pub extern "C" fn fibonacci(n: i32) -> i32 {
    if n <= 1 {
        return n;
    }
    let mut a = 0i32;
    let mut b = 1i32;
    let mut _i = 2i32;
    while _i <= n {
        let tmp = a + b;
        a = b;
        b = tmp;
        _i += 1;
    }
    b
}

/// Greet — returns a pointer to a static string.
#[no_mangle]
pub extern "C" fn greet() -> i32 {
    42
}

/// Memory export for JS interop.
#[no_mangle]
pub static mut MEMORY: [u8; 256] = [0u8; 256];
