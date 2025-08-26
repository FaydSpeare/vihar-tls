macro_rules! impl_state_dispatch {
    (
        [context = $context_name:path]
        [established = $established_name:ident]
        [closed = $closed_name:ident]
        pub enum $enum_name:ident {
            $($variant:ident($inner:ty)),+ $(,)?
        }
    ) => {

        #[derive(Debug)]
        pub enum $enum_name {
            $(
                $variant($inner),
            )+
        }

        $(
            impl From<$inner> for $enum_name {
                fn from(state: $inner) -> Self {
                    Self::$variant(state)
                }
            }
        )+

        impl TlsState<$context_name> for $enum_name {
            fn handle(self, ctx: &mut $context_name, event: TlsEvent) -> HandleResult<Self> {
                match self {
                    $(
                        Self::$variant(inner) => inner.handle(ctx, event),
                    )+
                }
            }

            fn is_established(&self) -> bool {
                matches!(self, Self::$established_name(_))
            }

            fn session_id(&self) -> Option<Vec<u8>> {
                match self {
                    Self::$established_name(state) => Some(state.session_id.to_vec()),
                    _ => None,
                }
            }

            fn new_closed_state() -> Self {
                Self::$closed_name(ClosedState {})
            }
        }
    };
}

#[macro_export]
macro_rules! pcs {
    ($priority:expr, $id:expr) => {
        $crate::client::PrioritisedCipherSuite {
            id: $id,
            priority: $priority,
        }
    };
}

macro_rules! require_handshake_msg {
    ($msg:expr, $handshake:path) => {
        match $msg {
            crate::state_machine::TlsEvent::IncomingMessage(
                crate::messages::TlsMessage::Handshake(handshake @ $handshake(inner)),
            ) => (handshake, inner),
            msg => {
                log::trace!("Expected: {:?}, but got: {:?}", stringify!($handshake), msg);
                return Err(crate::alert::AlertDesc::UnexpectedMessage);
            }
        }
    };
    ($msg:expr, $handshake:path, *) => {
        match $msg {
            crate::state_machine::TlsEvent::IncomingMessage(
                crate::messages::TlsMessage::Handshake(handshake @ $handshake),
            ) => handshake,
            _ => {
                return Err(crate::alert::AlertDesc::UnexpectedMessage);
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
