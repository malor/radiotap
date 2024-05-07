//! Radiotap struct builder.

use crate::field::*;
use crate::Radiotap;

/// A convenience struct for building [`Radiotap`] values in code. It takes
/// care of populating [`Radiotap::header`] based on which fields are set.
///
/// ```
/// use radiotap::Radiotap;
/// use radiotap::field::*;
///
/// let tap = Radiotap::build()
///     .rate(Rate { value: 15.0 })
///     .tsft(TSFT { value: 42 })
///     .flags(Flags {
///         wep: true,
///         fragmentation: true,
///         data_pad: true,
///         ..Default::default()
///     })
///     .done();
///
/// assert_eq!(
///     tap,
///     Radiotap {
///         header: Header {
///             version: 0,
///             size: 8,
///             length: 18,
///             present: vec![Kind::TSFT, Kind::Flags, Kind::Rate]
///         },
///         tsft: Some(TSFT { value: 42 }),
///         flags: Some(Flags {
///             wep: true,
///             fragmentation: true,
///             data_pad: true,
///             ..Default::default()
///         }),
///         rate: Some(Rate { value: 15.0 }),
///         ..Default::default()
///     }
/// );
/// ```
#[derive(Default)]
pub struct RadiotapBuilder {
    inner: Radiotap,
}

impl RadiotapBuilder {
    pub(crate) fn new() -> Self {
        RadiotapBuilder::default()
    }

    /// Returns a fully constructed [`Radiotap`] value.
    pub fn done(mut self) -> Radiotap {
        let header = &mut self.inner.header;

        // Setters can be called in any order, but we need to process fields in the order in which
        // they appear in the serialized format to correctly add up alignment/size values for each
        // present field.
        header.present.sort_by_key(|kind| kind.bit());
        header.length = header.present.iter().fold(header.length, |length, kind| {
            let size = kind.size();
            let align = kind.align() as usize;

            ((length + align - 1) & !(align - 1)) + size
        });

        self.inner
    }
}

macro_rules! field {
    ($name:ident, $type:ident) => {
        #[doc = concat!("Sets the value of the [`Radiotap::", stringify!($name), "`] field.")]
        pub fn $name(mut self, $name: $type) -> Self {
            if !self.inner.header.present.contains(&Kind::$type) {
                self.inner.header.present.push(Kind::$type);
            }

            self.inner.$name = Some($name);
            self
        }
    };
}
impl RadiotapBuilder {
    field!(tsft, TSFT);
    field!(flags, Flags);
    field!(rate, Rate);
    field!(channel, Channel);
    field!(fhss, FHSS);
    field!(antenna_signal, AntennaSignal);
    field!(antenna_noise, AntennaNoise);
    field!(lock_quality, LockQuality);
    field!(tx_attenuation, TxAttenuation);
    field!(tx_attenuation_db, TxAttenuationDb);
    field!(tx_power, TxPower);
    field!(antenna, Antenna);
    field!(antenna_signal_db, AntennaSignalDb);
    field!(antenna_noise_db, AntennaNoiseDb);
    field!(rx_flags, RxFlags);
    field!(tx_flags, TxFlags);
    field!(rts_retries, RTSRetries);
    field!(data_retries, DataRetries);
    field!(xchannel, XChannel);
    field!(mcs, MCS);
    field!(ampdu_status, AMPDUStatus);
    field!(vht, VHT);
    field!(timestamp, Timestamp);
}

#[cfg(test)]
mod tests {
    use crate::ext::*;

    use super::*;

    #[test]
    fn set_none() {
        let actual = Radiotap::build().done();
        let expected = Radiotap::default();
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_multiple() {
        let actual = Radiotap::build()
            .tsft(TSFT { value: 42 })
            .timestamp(Timestamp {
                timestamp: 700,
                unit: TimeUnit::Microseconds,
                position: SamplingPosition::StartMPDU,
                accuracy: None,
            })
            .rate(Rate { value: 15.0 })
            .flags(Flags {
                wep: true,
                fragmentation: true,
                data_pad: true,
                ..Default::default()
            })
            .channel(Channel {
                freq: 2500,
                flags: ChannelFlags {
                    turbo: true,
                    ..Default::default()
                },
            })
            .done();
        let expected = Radiotap {
            header: Header {
                version: 0,
                length: 36, // header length + length of all fields + alignment of the timestamp field
                size: 8,
                present: vec![
                    Kind::TSFT,
                    Kind::Flags,
                    Kind::Rate,
                    Kind::Channel,
                    Kind::Timestamp,
                ],
            },
            tsft: Some(TSFT { value: 42 }),
            flags: Some(Flags {
                wep: true,
                fragmentation: true,
                data_pad: true,
                ..Default::default()
            }),
            rate: Some(Rate { value: 15.0 }),
            channel: Some(Channel {
                freq: 2500,
                flags: ChannelFlags {
                    turbo: true,
                    ..Default::default()
                },
            }),
            timestamp: Some(Timestamp {
                timestamp: 700,
                unit: TimeUnit::Microseconds,
                position: SamplingPosition::StartMPDU,
                accuracy: None,
            }),
            ..Default::default()
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_twice() {
        let actual = Radiotap::build()
            .tsft(TSFT { value: 42 })
            .tsft(TSFT { value: 84 })
            .done();
        let expected = Radiotap {
            header: Header {
                version: 0,
                length: 16,
                size: 8,
                // only one entry in the present vector
                present: vec![Kind::TSFT],
            },
            // last update wins
            tsft: Some(TSFT { value: 84 }),
            ..Default::default()
        };
        assert_eq!(actual, expected);
    }

    macro_rules! test_field {
        ($name:ident, $kind:expr, $value:expr) => {
            #[test]
            fn $name() {
                let actual = RadiotapBuilder::new().$name($value).done();
                let expected = Radiotap {
                    header: Header {
                        version: 0,
                        length: 8 + $kind.size(),
                        size: 8,
                        present: vec![$kind],
                    },
                    $name: Some($value),
                    ..Default::default()
                };
                assert_eq!(actual, expected);
            }
        };
    }

    test_field!(tsft, Kind::TSFT, TSFT { value: 42 });
    test_field!(
        flags,
        Kind::Flags,
        Flags {
            fragmentation: true,
            data_pad: true,
            ..Default::default()
        }
    );
    test_field!(rate, Kind::Rate, Rate { value: 1.0 });
    test_field!(
        antenna_signal,
        Kind::AntennaSignal,
        AntennaSignal { value: -42 }
    );
    test_field!(
        antenna_noise,
        Kind::AntennaNoise,
        AntennaNoise { value: 42 }
    );
    test_field!(lock_quality, Kind::LockQuality, LockQuality { value: 14 });
    test_field!(
        tx_attenuation,
        Kind::TxAttenuation,
        TxAttenuation { value: 0 }
    );
    test_field!(
        tx_attenuation_db,
        Kind::TxAttenuationDb,
        TxAttenuationDb { value: 10 }
    );
    test_field!(tx_power, Kind::TxPower, TxPower { value: 17 });
    test_field!(antenna, Kind::Antenna, Antenna { value: 1 });
    test_field!(
        antenna_signal_db,
        Kind::AntennaSignalDb,
        AntennaSignalDb { value: 13 }
    );
    test_field!(
        antenna_noise_db,
        Kind::AntennaNoiseDb,
        AntennaNoiseDb { value: 12 }
    );
    test_field!(rx_flags, Kind::RxFlags, RxFlags { bad_plcp: true });
    test_field!(
        tx_flags,
        Kind::TxFlags,
        TxFlags {
            no_ack: true,
            rts: true,
            ..Default::default()
        }
    );
    test_field!(rts_retries, Kind::RTSRetries, RTSRetries { value: 44 });
    test_field!(data_retries, Kind::DataRetries, DataRetries { value: 0 });
    test_field!(
        xchannel,
        Kind::XChannel,
        XChannel {
            flags: XChannelFlags {
                turbo: true,
                ..Default::default()
            },
            freq: 2400,
            channel: 42,
            max_power: 10
        }
    );
    test_field!(
        mcs,
        Kind::MCS,
        MCS {
            index: Some(42),
            ..Default::default()
        }
    );
    test_field!(
        ampdu_status,
        Kind::AMPDUStatus,
        AMPDUStatus {
            reference: 10,
            zero_length: Some(true),
            ..Default::default()
        }
    );
    test_field!(
        vht,
        Kind::VHT,
        VHT {
            beamformed: Some(true),
            ..Default::default()
        }
    );
    test_field!(
        timestamp,
        Kind::Timestamp,
        Timestamp {
            timestamp: 600,
            unit: TimeUnit::Milliseconds,
            position: SamplingPosition::EndMPDU,
            accuracy: None
        }
    );
}
