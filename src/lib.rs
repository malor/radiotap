//! A parser for the [Radiotap](http://www.radiotap.org/) capture format.
//!
//! # Usage
//!
//! ## Parsing Radiotap data
//!
//! The `Radiotap::from_bytes(&capture)` constructor will parse all present
//! fields into a [Radiotap](struct.Radiotap.html) struct:
//!
//! ```
//! use radiotap::Radiotap;
//!
//! let capture = [
//!     0, 0, 56, 0, 107, 8, 52, 0, 185, 31, 155, 154, 0, 0, 0, 0, 20, 0, 124, 21, 64, 1, 213,
//!     166, 1, 0, 0, 0, 64, 1, 1, 0, 124, 21, 100, 34, 249, 1, 0, 0, 0, 0, 0, 0, 255, 1, 80,
//!     4, 115, 0, 0, 0, 1, 63, 0, 0,
//! ];
//!
//! let radiotap = Radiotap::from_bytes(&capture).unwrap();
//! println!("{:?}", radiotap.vht);
//! ```
//!
//! If you just want to parse a few specific fields from the Radiotap capture
//! you can create an iterator using `RadiotapIterator::from_bytes(&capture)`:
//!
//! ```
//! use radiotap::{field, RadiotapIterator};
//!
//! let capture = [
//!     0, 0, 56, 0, 107, 8, 52, 0, 185, 31, 155, 154, 0, 0, 0, 0, 20, 0, 124, 21, 64, 1, 213,
//!     166, 1, 0, 0, 0, 64, 1, 1, 0, 124, 21, 100, 34, 249, 1, 0, 0, 0, 0, 0, 0, 255, 1, 80,
//!     4, 115, 0, 0, 0, 1, 63, 0, 0,
//! ];
//!
//! for element in RadiotapIterator::from_bytes(&capture).unwrap() {
//!     match element {
//!         Ok((field::Kind::VHT, data)) => {
//!             let vht: field::VHT = field::from_bytes(data).unwrap();
//!             println!("{:?}", vht);
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Building Radiotap packets
//!
//! It is also possible to build Radiotap packets programmatically (e.g. to be used
//! for packet injection):
//!
//! ```
//! use std::io::Cursor;
//!
//! use radiotap::Radiotap;
//! use radiotap::field::*;
//! use radiotap::field::ext::*;
//!
//! // Build a Radiotap value (the header will be populated automatically).
//! let radiotap = Radiotap::build()
//!     .tsft(TSFT { value: 42 })
//!     .flags(Flags {
//!         wep: true,
//!         data_pad: true,
//!         ..Default::default()
//!     })
//!     .rate(Rate { value: 4.5 })
//!     .channel(Channel {
//!         freq: 2400,
//!         flags: ChannelFlags {
//!             turbo: true,
//!             ..Default::default()
//!         },
//!     })
//!     .fhss(FHSS {
//!         hopset: 1,
//!         pattern: 2,
//!     })
//!     .done();
//!
//! // Serialize the value into a stream of bytes according to the Radiotap format rules.
//! let mut buff = Cursor::new(Vec::new());
//! radiotap.unparse(&mut buff).unwrap();
//! ```

pub mod builder;
pub mod field;

use std::io::Write;
use std::{io::Cursor, result};

use crate::builder::RadiotapBuilder;
use crate::field::*;

/// All errors returned and used by the radiotap module.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The internal cursor on the data returned an IO error.
    #[error(transparent)]
    ParseError(#[from] std::io::Error),

    /// The given data is not a complete Radiotap capture.
    #[error("incomplete radiotap capture")]
    IncompleteError,

    /// The given data is shorter than the amount specified in the Radiotap header.
    #[error("invalid radiotap length")]
    InvalidLength,

    /// The given data is not a valid Radiotap capture.
    #[error("invalid radiotap capture")]
    InvalidFormat,

    /// Unsupported Radiotap header version.
    #[error("unsupported radiotap header version")]
    UnsupportedVersion,

    /// Unsupported Radiotap field.
    #[error("unsupported radiotap field")]
    UnsupportedField,
}

type Result<T> = result::Result<T, Error>;

/// A trait to align an offset to particular word size, usually 1, 2, 4, or 8.
trait Align {
    /// Aligns the offset to `align` size.
    fn align(&mut self, align: u64);
}

impl<T> Align for Cursor<T> {
    /// Aligns the Cursor position to `align` size.
    fn align(&mut self, align: u64) {
        let p = self.position();
        self.set_position((p + align - 1) & !(align - 1));
    }
}

/// Represents an unparsed Radiotap capture format, only the header field is
/// parsed.
#[derive(Debug, Clone)]
pub struct RadiotapIterator<'a> {
    header: Header,
    data: &'a [u8],
}

impl<'a> RadiotapIterator<'a> {
    pub fn from_bytes(input: &'a [u8]) -> Result<RadiotapIterator<'a>> {
        Ok(RadiotapIterator::parse(input)?.0)
    }

    pub fn parse(input: &'a [u8]) -> Result<(RadiotapIterator<'a>, &'a [u8])> {
        let header: Header = from_bytes(input)?;
        let (data, rest) = input.split_at(header.length);
        Ok((RadiotapIterator { header, data }, rest))
    }
}

/// An iterator over Radiotap fields.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RadiotapIteratorIntoIter<'a> {
    present: Vec<Kind>,
    cursor: Cursor<&'a [u8]>,
}

impl<'a> IntoIterator for &'a RadiotapIterator<'a> {
    type IntoIter = RadiotapIteratorIntoIter<'a>;
    type Item = Result<(Kind, &'a [u8])>;

    fn into_iter(self) -> Self::IntoIter {
        let present = self.header.present.iter().rev().cloned().collect();
        let mut cursor = Cursor::new(self.data);
        cursor.set_position(self.header.size as u64);
        RadiotapIteratorIntoIter { present, cursor }
    }
}

impl<'a> IntoIterator for RadiotapIterator<'a> {
    type IntoIter = RadiotapIteratorIntoIter<'a>;
    type Item = Result<(Kind, &'a [u8])>;

    fn into_iter(self) -> Self::IntoIter {
        let present = self.header.present.iter().rev().cloned().collect();
        let mut cursor = Cursor::new(self.data);
        cursor.set_position(self.header.size as u64);
        RadiotapIteratorIntoIter { present, cursor }
    }
}

impl<'a> Iterator for RadiotapIteratorIntoIter<'a> {
    type Item = Result<(Kind, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.present.pop() {
            Some(mut kind) => {
                // Align the cursor to the current field's needed alignment.
                self.cursor.align(kind.align());

                let mut start = self.cursor.position() as usize;
                let mut end = start + kind.size();

                // The header lied about how long the body was
                if end > self.cursor.get_ref().len() {
                    Some(Err(Error::IncompleteError))
                } else {
                    // Switching to a vendor namespace, and we don't know how to handle
                    // so we just return the entire vendor namespace section
                    if kind == Kind::VendorNamespace(None) {
                        match VendorNamespace::from_bytes(&self.cursor.get_ref()[start..end]) {
                            Ok(vns) => {
                                start += kind.size();
                                end += vns.skip_length as usize;
                                kind = Kind::VendorNamespace(Some(vns));
                            }
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    let data = &self.cursor.get_ref()[start..end];
                    self.cursor.set_position(end as u64);
                    Some(Ok((kind, data)))
                }
            }
            None => None,
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header {
            version: 0,
            length: 8,
            present: Vec::new(),
            size: 8,
        }
    }
}

/// Represents a parsed Radiotap capture, including the parsed header and all
/// fields as Option members.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Radiotap {
    pub header: Header,
    pub tsft: Option<TSFT>,
    pub flags: Option<Flags>,
    pub rate: Option<Rate>,
    pub channel: Option<Channel>,
    pub fhss: Option<FHSS>,
    pub antenna_signal: Option<AntennaSignal>,
    pub antenna_noise: Option<AntennaNoise>,
    pub lock_quality: Option<LockQuality>,
    pub tx_attenuation: Option<TxAttenuation>,
    pub tx_attenuation_db: Option<TxAttenuationDb>,
    pub tx_power: Option<TxPower>,
    pub antenna: Option<Antenna>,
    pub antenna_signal_db: Option<AntennaSignalDb>,
    pub antenna_noise_db: Option<AntennaNoiseDb>,
    pub rx_flags: Option<RxFlags>,
    pub tx_flags: Option<TxFlags>,
    pub rts_retries: Option<RTSRetries>,
    pub data_retries: Option<DataRetries>,
    pub xchannel: Option<XChannel>,
    pub mcs: Option<MCS>,
    pub ampdu_status: Option<AMPDUStatus>,
    pub vht: Option<VHT>,
    pub timestamp: Option<Timestamp>,
}

impl Radiotap {
    /// Returns a [`RadiotapBuilder`] used for programmatically constructing a [`Radiotap`] value.
    pub fn build() -> RadiotapBuilder {
        RadiotapBuilder::new()
    }

    /// Returns the parsed [Radiotap](struct.Radiotap.html) from an input byte
    /// array.
    pub fn from_bytes(input: &[u8]) -> Result<Radiotap> {
        Ok(Radiotap::parse(input)?.0)
    }

    /// Returns the parsed [Radiotap](struct.Radiotap.html) and remaining data
    /// from an input byte array.
    pub fn parse(input: &[u8]) -> Result<(Radiotap, &[u8])> {
        let (iterator, rest) = RadiotapIterator::parse(input)?;

        let mut radiotap = Radiotap {
            header: iterator.header.clone(),
            ..Default::default()
        };

        for result in &iterator {
            let (field_kind, data) = result?;

            match field_kind {
                Kind::TSFT => radiotap.tsft = from_bytes_some(data)?,
                Kind::Flags => radiotap.flags = from_bytes_some(data)?,
                Kind::Rate => radiotap.rate = from_bytes_some(data)?,
                Kind::Channel => radiotap.channel = from_bytes_some(data)?,
                Kind::FHSS => radiotap.fhss = from_bytes_some(data)?,
                Kind::AntennaSignal => radiotap.antenna_signal = from_bytes_some(data)?,
                Kind::AntennaNoise => radiotap.antenna_noise = from_bytes_some(data)?,
                Kind::LockQuality => radiotap.lock_quality = from_bytes_some(data)?,
                Kind::TxAttenuation => radiotap.tx_attenuation = from_bytes_some(data)?,
                Kind::TxAttenuationDb => radiotap.tx_attenuation_db = from_bytes_some(data)?,
                Kind::TxPower => radiotap.tx_power = from_bytes_some(data)?,
                Kind::Antenna => radiotap.antenna = from_bytes_some(data)?,
                Kind::AntennaSignalDb => radiotap.antenna_signal_db = from_bytes_some(data)?,
                Kind::AntennaNoiseDb => radiotap.antenna_noise_db = from_bytes_some(data)?,
                Kind::RxFlags => radiotap.rx_flags = from_bytes_some(data)?,
                Kind::TxFlags => radiotap.tx_flags = from_bytes_some(data)?,
                Kind::RTSRetries => radiotap.rts_retries = from_bytes_some(data)?,
                Kind::DataRetries => radiotap.data_retries = from_bytes_some(data)?,
                Kind::XChannel => radiotap.xchannel = from_bytes_some(data)?,
                Kind::MCS => radiotap.mcs = from_bytes_some(data)?,
                Kind::AMPDUStatus => radiotap.ampdu_status = from_bytes_some(data)?,
                Kind::VHT => radiotap.vht = from_bytes_some(data)?,
                Kind::Timestamp => radiotap.timestamp = from_bytes_some(data)?,
                _ => {}
            }
        }

        Ok((radiotap, rest))
    }

    /// Serializes a [Radiotap](struct.Radiotap.html) value into a stream of bytes.
    /// Returns the size of the serialized Radiotap data in bytes or the encountered error.
    pub fn unparse<W: Write>(&self, mut writer: W) -> Result<usize> {
        let mut size = 0;

        size += self.header.unparse(&mut writer)?;
        for field_kind in self.header.present.iter() {
            let align = field_kind.align() as usize;

            let aligned_size = (size + align - 1) & !(align - 1);
            while size < aligned_size {
                size += writer.write(b"\x00")?;
            }

            let writer = &mut writer;
            size += match field_kind {
                Kind::TSFT => unparse_some(writer, self.tsft.as_ref())?,
                Kind::Flags => unparse_some(writer, self.flags.as_ref())?,
                Kind::Rate => unparse_some(writer, self.rate.as_ref())?,
                Kind::Channel => unparse_some(writer, self.channel.as_ref())?,
                Kind::FHSS => unparse_some(writer, self.fhss.as_ref())?,
                Kind::AntennaSignal => unparse_some(writer, self.antenna_signal.as_ref())?,
                Kind::AntennaNoise => unparse_some(writer, self.antenna_noise.as_ref())?,
                Kind::LockQuality => unparse_some(writer, self.lock_quality.as_ref())?,
                Kind::TxAttenuation => unparse_some(writer, self.tx_attenuation.as_ref())?,
                Kind::TxAttenuationDb => unparse_some(writer, self.tx_attenuation_db.as_ref())?,
                Kind::TxPower => unparse_some(writer, self.tx_power.as_ref())?,
                Kind::Antenna => unparse_some(writer, self.antenna.as_ref())?,
                Kind::AntennaSignalDb => unparse_some(writer, self.antenna_signal_db.as_ref())?,
                Kind::AntennaNoiseDb => unparse_some(writer, self.antenna_noise_db.as_ref())?,
                Kind::RxFlags => unparse_some(writer, self.rx_flags.as_ref())?,
                Kind::TxFlags => unparse_some(writer, self.tx_flags.as_ref())?,
                Kind::RTSRetries => unparse_some(writer, self.rts_retries.as_ref())?,
                Kind::DataRetries => unparse_some(writer, self.data_retries.as_ref())?,
                Kind::XChannel => unparse_some(writer, self.xchannel.as_ref())?,
                Kind::MCS => unparse_some(writer, self.mcs.as_ref())?,
                Kind::AMPDUStatus => unparse_some(writer, self.ampdu_status.as_ref())?,
                Kind::VHT => unparse_some(writer, self.vht.as_ref())?,
                Kind::Timestamp => unparse_some(writer, self.timestamp.as_ref())?,
                _ => 0,
            };
        }

        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ext::*;

    #[test]
    fn good_vendor() {
        let frame = [
            0, 0, 39, 0, 46, 72, 0, 192, 0, 0, 0, 128, 0, 0, 0, 160, 4, 0, 0, 0, 16, 2, 158, 9,
            160, 0, 227, 5, 0, 0, 255, 255, 255, 255, 2, 0, 222, 173, 4,
        ];

        assert_eq!(
            Radiotap::from_bytes(&frame).unwrap().rate.unwrap(),
            Rate { value: 2.0 }
        );
    }

    #[test]
    fn bad_version() {
        let frame = [
            1, 0, 39, 0, 46, 72, 0, 192, 0, 0, 0, 128, 0, 0, 0, 160, 4, 0, 0, 0, 16, 2, 158, 9,
            160, 0, 227, 5, 0, 0, 255, 255, 255, 255, 2, 0, 222, 173, 4,
        ];

        match Radiotap::from_bytes(&frame).unwrap_err() {
            Error::UnsupportedVersion => {}
            e => panic!("Error not UnsupportedVersion: {:?}", e),
        };
    }

    #[test]
    fn bad_header_length() {
        let frame = [
            0, 0, 40, 0, 46, 72, 0, 192, 0, 0, 0, 128, 0, 0, 0, 160, 4, 0, 0, 0, 16, 2, 158, 9,
            160, 0, 227, 5, 0, 0, 255, 255, 255, 255, 2, 0, 222, 173, 4,
        ];

        match Radiotap::from_bytes(&frame).unwrap_err() {
            Error::InvalidLength => {}
            e => panic!("Error not InvalidLength: {:?}", e),
        };
    }

    #[test]
    fn bad_actual_length() {
        let frame = [
            0, 0, 39, 0, 47, 72, 0, 192, 0, 0, 0, 128, 0, 0, 0, 160, 4, 0, 0, 0, 16, 2, 158, 9,
            160, 0, 227, 5, 0, 0, 255, 255, 255, 255, 2, 0, 222, 173, 4,
        ];

        match Radiotap::from_bytes(&frame).unwrap_err() {
            Error::IncompleteError => {}
            e => panic!("Error not IncompleteError: {:?}", e),
        };
    }

    #[test]
    fn bad_vendor() {
        let frame = [
            0, 0, 34, 0, 46, 72, 0, 192, 0, 0, 0, 128, 0, 0, 0, 160, 4, 0, 0, 0, 16, 2, 158, 9,
            160, 0, 227, 5, 0, 0, 255, 255, 255, 255,
        ];

        match Radiotap::from_bytes(&frame).unwrap_err() {
            Error::IncompleteError => {}
            e => panic!("Error not IncompleteError: {:?}", e),
        };
    }

    #[test]
    fn unparse() {
        let reference = Radiotap::build()
            .tsft(TSFT { value: 42 })
            .flags(Flags {
                wep: true,
                data_pad: true,
                ..Default::default()
            })
            .rate(Rate { value: 4.5 })
            .channel(Channel {
                freq: 2400,
                flags: ChannelFlags {
                    turbo: true,
                    ..Default::default()
                },
            })
            .fhss(FHSS {
                hopset: 1,
                pattern: 2,
            })
            .antenna_signal(AntennaSignal { value: 1 })
            .antenna_noise(AntennaNoise { value: 2 })
            .lock_quality(LockQuality { value: 3 })
            .tx_attenuation(TxAttenuation { value: 4 })
            .tx_attenuation_db(TxAttenuationDb { value: 5 })
            .tx_power(TxPower { value: 6 })
            .antenna(Antenna { value: 7 })
            .antenna_signal_db(AntennaSignalDb { value: 8 })
            .antenna_noise_db(AntennaNoiseDb { value: 9 })
            .rx_flags(RxFlags { bad_plcp: true })
            .tx_flags(TxFlags {
                fail: true,
                cts: false,
                rts: true,
                ..Default::default()
            })
            .rts_retries(RTSRetries { value: 1 })
            .data_retries(DataRetries { value: 2 })
            .xchannel(XChannel {
                flags: XChannelFlags {
                    turbo: true,
                    cck: false,
                    ofdm: true,
                    ghz2: true,
                    gsm: true,
                    sturbo: false,
                    half: true,
                    ..Default::default()
                },
                freq: 1234,
                channel: 42,
                max_power: 24,
            })
            .ampdu_status(AMPDUStatus {
                reference: 17,
                zero_length: Some(true),
                last: Some(false),
                delimiter_crc: Some(42),
            })
            .timestamp(Timestamp {
                timestamp: 1234,
                unit: TimeUnit::Nanoseconds,
                position: SamplingPosition::StartMPDU,
                accuracy: Some(1234),
            })
            .mcs(MCS {
                bw: Some(Bandwidth::new(3).unwrap()),
                index: Some(1),
                gi: Some(GuardInterval::Short),
                format: Some(HTFormat::Greenfield),
                fec: Some(FEC::BCC),
                stbc: Some(3),
                ness: Some(2),
                datarate: Some(30.0),
            })
            .vht(VHT {
                stbc: Some(true),
                txop_ps: Some(false),
                gi: Some(GuardInterval::Long),
                sgi_nsym_da: Some(false),
                ldpc_extra: Some(true),
                beamformed: Some(true),
                bw: Some(Bandwidth::new(4).unwrap()),
                group_id: Some(42),
                partial_aid: Some(1234),
                users: [
                    None,
                    None,
                    Some(VHTUser {
                        index: 1,
                        fec: FEC::LDPC,
                        nss: 4,
                        nsts: 8,
                        datarate: Some(234.0),
                    }),
                    None,
                ],
            })
            .done();

        // unparse() followed by parse() must return the original value.
        let mut buff = Cursor::new(Vec::new());
        let length = reference.unparse(&mut buff).unwrap();
        let actual = Radiotap::parse(&buff.into_inner()).unwrap().0;
        assert_eq!(actual.header.length, length);
        assert_eq!(actual, reference);
    }
}
