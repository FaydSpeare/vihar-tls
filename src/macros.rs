macro_rules! require_handshake_msg {
    ($msg:expr, $handshake:path) => {
        match $msg {
            crate::state_machine::TlsEvent::IncomingMessage(
                crate::messages::TlsMessage::Handshake(handshake @ $handshake(inner)),
            ) => (handshake, inner),
            _ => {
                return Ok((
                    ClosedState {}.into(),
                    vec![TlsAction::SendAlert(TlsAlert::fatal(
                        TlsAlertDesc::UnexpectedMessage,
                    ))],
                ))
            }
        }
    };
    ($msg:expr, $handshake:path, *) => {
        match $msg {
            crate::state_machine::TlsEvent::IncomingMessage(
                crate::messages::TlsMessage::Handshake(handshake @ $handshake),
            ) => handshake,
            _ => {
                return Ok((
                    ClosedState {}.into(),
                    vec![TlsAction::SendAlert(TlsAlert::fatal(
                        TlsAlertDesc::UnexpectedMessage,
                    ))],
                ))
            }
        }
    };
}

macro_rules! tls_codable_enum {
    (
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
          $($enum_var:ident = $enum_val:literal),* $(,)?
        }
    ) => {

        #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
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

            fn read_from(reader: &mut crate::encoding::Reader) -> Result<Self, crate::errors::DecodingError> {
                let value = <$uint>::read_from(reader)?;
                Ok(Self::from(value))
            }
        }
    }
}

macro_rules! u16_vec_len_with_max {
    ($name:ident, $max:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(u16);

        impl $name {
            pub const MAX: u16 = $max;
            pub fn new(value: u16) -> Option<Self> {
                (value <= Self::MAX).then_some(Self(value))
            }
        }

        impl TlsCodable for $name {
            fn write_to(&self, bytes: &mut Vec<u8>) {
                self.0.write_to(bytes)
            }

            // TODO check if value is < MAX
            fn read_from(reader: &mut Reader) -> Result<Self, crate::errors::DecodingError> {
                Ok(Self(u16::read_from(reader)?))
            }
        }

        impl From<$name> for usize {
            fn from(value: $name) -> Self {
                value.0 as Self
            }
        }

        impl VecLen for $name {
            const BYTE_LEN: usize = 2;
            const MAX_LEN: usize = Self::MAX as usize;

            // TODO, if > Max then this will throw, but the error is ignored in veclen
            fn from_usize(value: usize) -> Result<Self, String> {
                let value = u16::try_from(value).map_err(|_| "invalid length".to_string())?;
                Self::new(value).ok_or("invalid length".to_string())
            }
            fn encode_into_slice(&self, out: &mut [u8]) {
                out.copy_from_slice(&self.0.to_be_bytes());
            }
        }
    };
}
