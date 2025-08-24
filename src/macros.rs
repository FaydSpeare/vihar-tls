macro_rules! impl_state_dispatch {
    (
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

        impl HandleRecord<$enum_name> for $enum_name {
            fn handle(self, ctx: &mut TlsContext, event: TlsEvent) -> HandleResult<$enum_name> {
                match self {
                    $(
                        Self::$variant(inner) => inner.handle(ctx, event),
                    )+
                }
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
                return Ok((
                    crate::state_machine::ClosedState {}.into(),
                    vec![crate::state_machine::TlsAction::SendAlert(TlsAlert::fatal(
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
                    crate::state_machine::ClosedState {}.into(),
                    vec![crate::state_machine::TlsAction::SendAlert(TlsAlert::fatal(
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
