// Licensed under the Apache-2.0 license

//! Macros that generate `Unaligned` bit-flag newtypes with
//! bitflags-style API (`contains`, `intersects`, `|`, `&`,
//! `pick_lowest`).
//!
//! Two flavors:
//!
//! - [`def_flag_set_le!`] for multi-byte storage (`le::U16` /
//!   `le::U32`). The newtype is `#[repr(transparent)]` over the LE
//!   byte-array type (alignment 1, `Unaligned` ✓), so it can sit
//!   directly inside `#[repr(C)] Unaligned` wire PDU structs.
//! - [`def_flag_set_u8!`] for single-byte storage (no LE wrapper
//!   needed).
//!
//! Generated API per type:
//! ```ignore
//! const EMPTY: Self;
//! const NAMED_BIT: Self;          // one per declared constant
//! const fn from_bits(bits: native) -> Self;
//! fn into_bits(self) -> native;
//! fn is_empty(self) -> bool;
//! fn contains(self, other: Self) -> bool;
//! fn intersects(self, other: Self) -> bool;
//! fn pick_lowest(self, other: Self) -> Self;
//! impl BitOr / BitOrAssign / BitAnd
//! ```

/// Define an `Unaligned` bit-flag newtype with `le::U16` or `le::U32`
/// storage. Pass the LE storage type and its native primitive.
macro_rules! def_flag_set_le {
    (
        $(#[$attr:meta])*
        pub struct $name:ident($le:ty: $native:ty) {
            $($(#[$cattr:meta])* $cname:ident = $cval:expr),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(::zerocopy::FromBytes, ::zerocopy::IntoBytes,
                 ::zerocopy::KnownLayout, ::zerocopy::Immutable,
                 ::zerocopy::Unaligned, Copy, Clone, Default, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name($le);

        #[allow(dead_code)]
        impl $name {
            pub const EMPTY: Self = Self(<$le>::ZERO);
            $(
                $(#[$cattr])*
                pub const $cname: Self = Self(<$le>::new($cval));
            )*

            #[inline] pub const fn from_bits(bits: $native) -> Self { Self(<$le>::new(bits)) }
            #[inline] pub fn into_bits(self) -> $native { self.0.get() }

            /// `const fn` OR — usable in `const` initializers, unlike
            /// the `BitOr` operator which can't be `const` because of
            /// the `le::U*::get()` call inside `into_bits`.
            ///
            /// This works because we reach into the underlying LE byte
            /// array directly using `.0.to_bytes()` is not const either;
            /// instead we cast through `Self`'s known-layout u8 bytes.
            #[inline] pub const fn const_or(self, other: Self) -> Self {
                // SAFETY-free: every byte position can be OR'd at the
                // u8 level because the storage is just bytes — the LE
                // wrapper has no semantic content beyond byte order.
                let mut out = [0u8; core::mem::size_of::<$native>()];
                let a = self.0.to_bytes();
                let b = other.0.to_bytes();
                let mut i = 0;
                while i < out.len() {
                    out[i] = a[i] | b[i];
                    i += 1;
                }
                Self(<$le>::from_bytes(out))
            }

            #[inline] pub fn is_empty(self) -> bool { self.into_bits() == 0 }
            #[inline] pub fn contains(self, other: Self) -> bool {
                let s = self.into_bits();
                let o = other.into_bits();
                (s & o) == o
            }
            #[inline] pub fn intersects(self, other: Self) -> bool {
                (self.into_bits() & other.into_bits()) != 0
            }
            /// Lowest set bit of `(self & other)`, or `EMPTY`.
            /// Implements the SPDM "pick one mutually-supported
            /// algorithm" rule.
            #[inline] pub fn pick_lowest(self, other: Self) -> Self {
                let common = self.into_bits() & other.into_bits();
                Self::from_bits(common & common.wrapping_neg())
            }
        }
        impl ::core::ops::BitOr for $name {
            type Output = Self;
            #[inline] fn bitor(self, r: Self) -> Self { Self::from_bits(self.into_bits() | r.into_bits()) }
        }
        impl ::core::ops::BitOrAssign for $name {
            #[inline] fn bitor_assign(&mut self, r: Self) { *self = *self | r; }
        }
        impl ::core::ops::BitAnd for $name {
            type Output = Self;
            #[inline] fn bitand(self, r: Self) -> Self { Self::from_bits(self.into_bits() & r.into_bits()) }
        }
    };
}

/// Same as [`def_flag_set_le`] but for `u8`-backed flag types
/// (no LE wrapper needed since `align_of::<u8>() == 1`).
macro_rules! def_flag_set_u8 {
    (
        $(#[$attr:meta])*
        pub struct $name:ident {
            $($(#[$cattr:meta])* $cname:ident = $cval:expr),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(::zerocopy::FromBytes, ::zerocopy::IntoBytes,
                 ::zerocopy::KnownLayout, ::zerocopy::Immutable,
                 ::zerocopy::Unaligned, Copy, Clone, Default, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(u8);

        #[allow(dead_code)]
        impl $name {
            pub const EMPTY: Self = Self(0);
            $(
                $(#[$cattr])*
                pub const $cname: Self = Self($cval);
            )*

            #[inline] pub const fn from_bits(bits: u8) -> Self { Self(bits) }
            #[inline] pub const fn into_bits(self) -> u8 { self.0 }
            /// `const fn` OR — usable in `const` initializers.
            #[inline] pub const fn const_or(self, other: Self) -> Self { Self(self.0 | other.0) }
            #[inline] pub fn is_empty(self) -> bool { self.0 == 0 }
            #[inline] pub fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
            #[inline] pub fn intersects(self, other: Self) -> bool { (self.0 & other.0) != 0 }
            #[inline] pub fn pick_lowest(self, other: Self) -> Self {
                let common = self.0 & other.0;
                Self(common & common.wrapping_neg())
            }
        }
        impl ::core::ops::BitOr for $name {
            type Output = Self;
            #[inline] fn bitor(self, r: Self) -> Self { Self(self.0 | r.0) }
        }
        impl ::core::ops::BitOrAssign for $name {
            #[inline] fn bitor_assign(&mut self, r: Self) { self.0 |= r.0; }
        }
        impl ::core::ops::BitAnd for $name {
            type Output = Self;
            #[inline] fn bitand(self, r: Self) -> Self { Self(self.0 & r.0) }
        }
    };
}

pub(crate) use def_flag_set_le;
pub(crate) use def_flag_set_u8;

#[cfg(test)]
mod tests {
    use zerocopy::{
        little_endian::{U16, U32},
        FromBytes, IntoBytes,
    };

    def_flag_set_le! {
        pub struct F32(U32: u32) {
            A = 1 << 0,
            B = 1 << 1,
            C = 1 << 8,
            D = 1 << 31,
        }
    }

    def_flag_set_le! {
        pub struct F16(U16: u16) {
            A = 1 << 0,
            HI = 1 << 15,
        }
    }

    def_flag_set_u8! {
        pub struct F8 {
            A = 1 << 0,
            B = 1 << 1,
            HI = 1 << 7,
        }
    }

    #[test]
    fn test_layout_is_unaligned_and_native_sized() {
        assert_eq!(core::mem::size_of::<F32>(), 4);
        assert_eq!(core::mem::align_of::<F32>(), 1);
        assert_eq!(core::mem::size_of::<F16>(), 2);
        assert_eq!(core::mem::align_of::<F16>(), 1);
        assert_eq!(core::mem::size_of::<F8>(), 1);
        assert_eq!(core::mem::align_of::<F8>(), 1);
    }

    #[test]
    fn test_wire_bytes_are_little_endian() {
        assert_eq!(F32::from_bits(0x1234_5678).as_bytes(), &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(F16::from_bits(0x1234).as_bytes(), &[0x34, 0x12]);
        assert_eq!(F8::from_bits(0xAB).as_bytes(), &[0xAB]);

        // Decoding the same bytes gives the original value back.
        let f = F32::read_from_bytes(&[0x78, 0x56, 0x34, 0x12]).unwrap();
        assert_eq!(f.into_bits(), 0x1234_5678);
        let f = F16::read_from_bytes(&[0x34, 0x12]).unwrap();
        assert_eq!(f.into_bits(), 0x1234);

        // Named constants land in the expected byte lane: bit 8 is byte 1,
        // bit 31 is the top bit of byte 3.
        assert_eq!(F32::C.as_bytes(), &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(F32::D.as_bytes(), &[0x00, 0x00, 0x00, 0x80]);
        assert_eq!(F16::HI.as_bytes(), &[0x00, 0x80]);
    }

    #[test]
    fn test_empty_default_and_bits_roundtrip() {
        assert!(F32::EMPTY.is_empty());
        assert!(F32::default() == F32::EMPTY);
        assert_eq!(F32::EMPTY.into_bits(), 0);
        assert!(!F32::A.is_empty());
        assert_eq!(F32::from_bits(0xDEAD_BEEF).into_bits(), 0xDEAD_BEEF);
        assert_eq!(F16::from_bits(0xBEEF).into_bits(), 0xBEEF);
        assert_eq!(F8::from_bits(0xEF).into_bits(), 0xEF);
        assert!(F8::EMPTY.is_empty());
    }

    // Pins current behavior: from_bits does not mask to the declared constants,
    // so undefined bits survive a round trip.
    #[test]
    fn test_from_bits_keeps_undefined_bits() {
        assert_eq!(F8::from_bits(0xFF).into_bits(), 0xFF);
        assert_eq!(F32::from_bits(u32::MAX).into_bits(), u32::MAX);
    }

    #[test]
    fn test_contains_and_intersects() {
        let ab = F32::A | F32::B;
        assert!(ab.contains(F32::A));
        assert!(ab.contains(ab));
        // A superset is not contained in a subset.
        assert!(!F32::A.contains(ab));
        // Vacuous truth: everything contains EMPTY; EMPTY contains nothing else.
        assert!(F32::A.contains(F32::EMPTY));
        assert!(F32::EMPTY.contains(F32::EMPTY));
        assert!(!F32::EMPTY.contains(F32::A));

        assert!(ab.intersects(F32::B | F32::C));
        assert!(!ab.intersects(F32::C | F32::D));
        assert!(!ab.intersects(F32::EMPTY));

        assert!((F8::A | F8::HI).contains(F8::HI));
        assert!(!F8::A.contains(F8::B));
        assert!(F8::A.intersects(F8::A | F8::B));
    }

    #[test]
    fn test_bit_operators() {
        assert_eq!((F32::A | F32::D).into_bits(), 0x8000_0001);
        assert_eq!((F32::A | F32::B | F32::C).into_bits(), 0x103);
        assert_eq!(((F32::A | F32::B) & (F32::B | F32::C)).into_bits(), 0x2);
        assert!((F32::A & F32::B).is_empty());

        let mut f = F16::A;
        f |= F16::HI;
        assert_eq!(f.into_bits(), 0x8001);

        assert_eq!((F8::A | F8::HI).into_bits(), 0x81);
        assert_eq!(((F8::A | F8::B) & F8::B).into_bits(), 0x02);
        let mut g = F8::EMPTY;
        g |= F8::B;
        assert_eq!(g.into_bits(), 0x02);
    }

    #[test]
    fn test_const_or_works_in_const_context_and_matches_bitor() {
        const AD: F32 = F32::A.const_or(F32::D);
        const AHI: F16 = F16::A.const_or(F16::HI);
        const AB8: F8 = F8::A.const_or(F8::B);

        assert_eq!(AD.into_bits(), 0x8000_0001);
        // OR is applied per byte lane: bit 0 (byte 0) and bit 31 (byte 3).
        assert_eq!(AD.as_bytes(), &[0x01, 0x00, 0x00, 0x80]);
        assert!(AD == F32::A | F32::D);
        assert_eq!(AHI.into_bits(), 0x8001);
        assert_eq!(AB8.into_bits(), 0x03);
        assert!(F32::EMPTY.const_or(F32::C) == F32::C);
    }

    #[test]
    fn test_pick_lowest() {
        // Common bits are B and C; the lowest is B.
        let ours = F32::A | F32::B | F32::C;
        let theirs = F32::B | F32::C | F32::D;
        assert!(ours.pick_lowest(theirs) == F32::B);
        // Order of operands does not matter.
        assert!(theirs.pick_lowest(ours) == F32::B);

        // No common bits, or an empty side, selects nothing.
        assert!(F32::A.pick_lowest(F32::B).is_empty());
        assert!(F32::EMPTY.pick_lowest(F32::EMPTY).is_empty());
        assert!(ours.pick_lowest(F32::EMPTY).is_empty());

        // Top bit: wrapping_neg(0x8000_0000) == 0x8000_0000, so it still works.
        assert!(F32::D.pick_lowest(F32::D) == F32::D);
        assert!(F16::HI.pick_lowest(F16::HI | F16::A) == F16::HI);
        assert!(F8::HI.pick_lowest(F8::HI) == F8::HI);

        assert!((F8::A | F8::B).pick_lowest(F8::B | F8::HI) == F8::B);
        assert!(F8::A.pick_lowest(F8::B).is_empty());
    }
}
