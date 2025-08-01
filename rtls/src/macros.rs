macro_rules! tls_codable_enum {
    (
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
          $($enum_var:ident = $enum_val:literal),* $(,)?
        }
    ) => {

        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        #[repr($uint)]
        $enum_vis enum $enum_name {
            $(
                $enum_var
            ),*
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $(
                        $enum_name::$enum_var => $enum_val
                    ),*
                }
            }
        }

        impl TryFrom<$uint> for $enum_name {
            type Error = crate::encoding::CodingError;

            fn try_from(value: $uint) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $enum_val => Ok($enum_name::$enum_var)
                    ),*
                    ,v => Err(crate::encoding::CodingError::InvalidEnumValue(stringify!($enum_name), v as usize))
                }
            }
        }

        impl crate::encoding::TlsCodable for $enum_name {
            fn write_to(&self, bytes: &mut Vec<u8>) {
               <$uint>::from(*self).write_to(bytes);
            }

            fn read_from(reader: &mut crate::encoding::Reader) -> Result<Self, crate::encoding::CodingError> {
                let value = <$uint>::read_from(reader)?;
                Self::try_from(value)
            }
        }
    };
    (
        #[with_unknown]
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
          $($enum_var:ident = $enum_val:literal),* $(,)?
        }
    ) => {

        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        #[repr($uint)]
        $enum_vis enum $enum_name {
            $(
                $enum_var
            ),*
            ,Unknown($uint),
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $(
                        $enum_name::$enum_var => $enum_val
                    ),*
                    ,$enum_name::Unknown(v) => v,
                }
            }
        }

        impl From<$uint> for $enum_name {
            fn from(value: $uint) -> Self {
                match value {
                    $(
                        $enum_val => $enum_name::$enum_var
                    ),*
                    ,v => $enum_name::Unknown(v),
                }
            }
        }

        impl crate::encoding::TlsCodable for $enum_name {
            fn write_to(&self, bytes: &mut Vec<u8>) {
               <$uint>::from(*self).write_to(bytes);
            }

            fn read_from(reader: &mut crate::encoding::Reader) -> Result<Self, crate::encoding::CodingError> {
                let value = <$uint>::read_from(reader)?;
                Ok(Self::from(value))
            }
        }
    }

}
