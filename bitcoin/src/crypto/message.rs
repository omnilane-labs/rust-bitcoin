use core::fmt;

pub const MESSAGE_SIZE: usize = 32;

/// A (hashed) message input to an ECDSA signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message([u8; MESSAGE_SIZE]);

impl Message {
  /// Creates a [`Message`] from a 32 byte slice `digest`.
  ///
  /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
  /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
  /// the result of signing isn't a
  /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
  #[inline]
  #[deprecated(since = "0.28.0", note = "use from_digest instead")]
  pub fn from_slice(digest: &[u8]) -> Result<Message, Error> {
      #[allow(deprecated)]
      Message::from_digest_slice(digest)
  }

  /// Creates a [`Message`] from a `digest`.
  ///
  /// The `digest` array has to be a cryptographically secure hash of the actual message that's
  /// going to be signed. Otherwise the result of signing isn't a [secure signature].
  ///
  /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
  #[inline]
  pub fn from_digest(digest: [u8; 32]) -> Message { Message(digest) }

  /// Creates a [`Message`] from a 32 byte slice `digest`.
  ///
  /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
  /// message that's going to be signed. Otherwise the result of signing isn't a [secure
  /// signature].
  ///
  /// This method is deprecated. It's best to use [`Message::from_digest`] directly with an
  /// array. If your hash engine doesn't return an array for some reason use `.try_into()` on its
  /// output.
  ///
  /// # Errors
  ///
  /// If `digest` is not exactly 32 bytes long.
  ///
  /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
  #[inline]
  #[deprecated(since = "TBD", note = "use from_digest instead")]
  pub fn from_digest_slice(digest: &[u8]) -> Result<Message, Error> {
      Ok(Message::from_digest(digest.try_into().map_err(|_| Error::InvalidMessage)?))
  }
}

impl fmt::LowerHex for Message {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      for byte in self.0.iter() {
          write!(f, "{:02x}", byte)?;
      }
      Ok(())
  }
}

impl fmt::Display for Message {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Error {
    /// Bad sized message ("messages" are actually fixed-sized digests [`constants::MESSAGE_SIZE`]).
    InvalidMessage,
}
