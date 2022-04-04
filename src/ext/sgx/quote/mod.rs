//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! <https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf>
//!
//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! <https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf>

pub mod cast;
mod crypto;
pub mod error;
pub mod header;
pub mod report;
pub mod signature;
mod sizes;

use self::{
    cast::{report_body_from_bytes, slice_cast},
    header::{QuoteHeader, QuoteVersion},
    sizes::*,
};

use error::QuoteError;
use sgx::ReportBody;
use signature::SigData;

/// Section A.4
/// All integer fields are in little endian.
#[repr(C, align(4))]
pub struct Quote<'a> {
    /// Header for Quote structure; transparent to the user.
    pub header: QuoteHeader,
    /// The version specific quote body.
    pub body: QuoteBody<'a>,
}

impl<'a> Quote<'a> {
    /// Verify fields in the structure.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        self.header.verify()?;
        self.body.verify()?;
        Ok(())
    }
}

impl<'a> TryFrom<&'a [u8]> for Quote<'a> {
    type Error = QuoteError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let header =
            (*slice_cast::<QUOTE_HEADER_SIZE>("header", &bytes[0..QUOTE_HEADER_SIZE])?).into();
        let body = QuoteBody::try_from((&header, bytes))?;
        Ok(Self { header, body })
    }
}

/// Section A.4
/// All integer fields are in little endian.
#[derive(Debug, Clone)]
#[repr(C, align(4))]
#[non_exhaustive]
pub enum QuoteBody<'a> {
    V3(QuoteBodyV3<'a>),
}

impl<'a> QuoteBody<'a> {
    /// Verify fields in the structure.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        match self {
            QuoteBody::V3(quote) => quote.verify(),
        }
    }
}

impl<'a> TryFrom<(&QuoteHeader, &'a [u8])> for QuoteBody<'a> {
    type Error = QuoteError;

    fn try_from((header, bytes): (&QuoteHeader, &'a [u8])) -> Result<Self, Self::Error> {
        match header.version()? {
            QuoteVersion::V3 => Ok(QuoteBody::V3(QuoteBodyV3::try_from(bytes)?)),
        }
    }
}

/// Section A.4
/// All integer fields are in little endian.
///
/// Quote
/// |-----------
/// | -- QuoteHeader (48 bytes)
/// |    | -- ...
/// |
/// | -- ISV Enclave Report (384 bytes)
/// |    | -- ...
/// |    | -- ReportData (at offset 320 from Report start)
/// |
/// | -- Quote Sig Data Len (4 bytes)
/// |
/// | -- Quote Signature (length specified in Quote Sig Data Len)
/// |    | -- ISV Enclave Report Sig (64 bytes)
/// |    | -- AK Pub (64 bytes)
/// |    | -- QE Report (384 bytes)
/// |    |    | -- ...
/// |    |    | -- ReportData (at offset 320 from Report start)
/// |    | -- ...
/// |____________
#[derive(Debug, Clone)]
#[repr(C, align(4))]
pub struct QuoteBodyV3<'a> {
    report_body: ReportBody,
    sig_data_len: u32,
    sig_data: SigData<'a>,
}

impl<'a> QuoteBodyV3<'a> {
    /// Report of the atteste enclave.
    pub fn report_body(&self) -> &ReportBody {
        &self.report_body
    }

    /// Size of the Signature Data field.
    #[allow(unused)]
    pub fn sig_data_len(&self) -> u32 {
        self.sig_data_len
    }

    /// Variable-length data containing the signature and
    /// supporting data.
    pub fn sig_data(&self) -> &SigData<'a> {
        &self.sig_data
    }

    /// Verify fields in the structure.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        report::quote_report_body_verify(self.report_body())?;
        self.sig_data().verify()?;
        Ok(())
    }
}

impl<'a> TryFrom<&'a [u8]> for QuoteBodyV3<'a> {
    type Error = QuoteError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let report_body = *slice_cast::<REPORT_SIZE>(
            "isv enclave report",
            &bytes[QUOTE_HEADER_SIZE..(QUOTE_HEADER_SIZE + REPORT_SIZE)],
        )?;
        let report_body = report_body_from_bytes(report_body);
        let sig_data_len = u32::from_le_bytes(*slice_cast::<U32_SIZE>(
            "sig data len",
            &bytes[QUOTE_SIG_START - QUOTE_SIG_DATA_LEN_SIZE..QUOTE_SIG_START],
        )?);
        let expected_quote_len = QUOTE_SIG_START + sig_data_len as usize;
        let sig_data = SigData::try_from(&bytes[QUOTE_SIG_START..expected_quote_len])?;

        Ok(Self {
            report_body,
            sig_data_len,
            sig_data,
        })
    }
}