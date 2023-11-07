/// An exhausting, injective counter with exponential search properties
///
/// The type implements an [`Iterator`] that yields numbers from the range
/// from 0 to a pre-defined maximum.
///
/// * It is *exhausting* in that it visits all numbers inside `0..max`.
/// * It is *injective* in that all numbers are visited only once.
/// * It has *exponential search properties* in that it iterates over the
///   number range in a fractal pattern.
///
/// This iterator is well suited for finding a pivot in algorithms that
/// want centered pivots: its output is heavily biased towards starting
/// with small numbers.
///
/// If the specified maximum is close to an exponent
/// of two we will quickly reach that exponent and therefore we will
/// quickly close in on the maximum, contrary to the claim of the counter
/// providing centered pivots. For most algorithms, this is not a problem
/// though as long as this is only a limited number of times, which it does,
/// as the next maximum will be an exponent of two, for which the next
/// smaller one is precisely its half of. So we will be able to perform a
/// binary search in all instances.
pub struct ExpCounter {
    /// The (exclusive) upper limit of our search
    max: u64,
    /// The base that increases after each round trip
    base: u64,
    /// An increasing offset, always a power of two
    offs: u64,
    /// Iteration counter
    i: u64,
}

impl ExpCounter {
    /// Creates an iterator that uses `ExpCounter` for the first half of the
    /// range and a linear range counter for the second half.
    pub fn with_max_and_linear_search(max: u64) -> impl Iterator<Item = u64> {
        let linear_start = max / 2;
        ExpCounter::with_max(linear_start).chain(linear_start..max)
    }
    /// Creates a new `ExpCounter` instance that counts to the (exclusive) maximum
    pub fn with_max(max: u64) -> Self {
        Self {
            max,
            base: 0,
            offs: 1,
            i: 0,
        }
    }
}

impl Iterator for ExpCounter {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.max {
            return None;
        }
        if self.i == 0 {
            // Special casing this is easier than adding 0 as the first in some other fashion
            self.i += 1;
            return Some(0);
        }
        let to_yield = self.base + self.offs;
        self.offs *= 2;

        if self.base + self.offs >= self.max {
            self.base += 1;
            self.offs = 1;
            while self.base > self.offs {
                self.offs *= 2;
            }
            if (self.base + self.offs).count_ones() == 1 {
                self.offs *= 2;
            }
        }
        self.i += 1;

        Some(to_yield)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;

    fn dupes_and_missing(list: &mut [u64], max: u64) -> (usize, usize) {
        let mut contained_in_list = HashSet::<u64>::new();
        let mut dupes = 0;
        let mut missing = 0;

        for v in list.iter() {
            println!("{v:4 } = {v:010b}");
        }
        println!("Yielded {} items", list.len());
        println!("The duplicates:");
        list.sort();
        let mut prev = None;
        for v in list.iter() {
            contained_in_list.insert(*v);
            if Some(*v) == prev {
                dupes += 1;
                println!("{v:3 } = {v:08b}");
            }
            prev = Some(*v);
        }
        println!("The missing numbers:");
        for v in 0..max {
            if !contained_in_list.contains(&v) {
                println!("{v:3 } = {v:010b}");
                missing += 1;
            }
        }
        (dupes, missing)
    }

    #[test]
    fn to_40() {
        let max = 40;
        let list = ExpCounter::with_max(max).collect::<Vec<_>>();
        let expected = [
            0, 1, 2, 4, 8, 16, 32, 3, 5, 9, 17, 33, 6, 10, 18, 34, 7, 11, 19, 35, 12, 20, 36, 13,
            21, 37, 14, 22, 38, 15, 23, 39, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        assert_eq!(list, expected);
    }

    #[test]
    fn to_64() {
        let max = 64;
        let mut list = ExpCounter::with_max(max).collect::<Vec<_>>();
        assert_eq!(dupes_and_missing(&mut list, max), (0, 0));
    }

    #[test]
    fn to_100() {
        let max = 100;
        let mut list = ExpCounter::with_max(max).collect::<Vec<_>>();
        assert_eq!(dupes_and_missing(&mut list, max), (0, 0));
    }

    #[test]
    fn to_127() {
        let max = 127;
        let mut list = ExpCounter::with_max(max).collect::<Vec<_>>();
        assert_eq!(dupes_and_missing(&mut list, max), (0, 0));
    }

    #[test]
    fn to_12345() {
        let max = 12345;
        let mut list = ExpCounter::with_max(max).collect::<Vec<_>>();
        assert_eq!(dupes_and_missing(&mut list, max), (0, 0));
    }
}
