<?php
namespace THansen\PhpVault;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Password;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use THansen\PhpVault\Exception\PhpVaultException;
use Throwable;

/**
 * Class PhpVault
 *
 * @package THansen\PhpVault
 * @author Thomas P. Hansen
 * @license LGPL v3
 */
class PhpVault
{
	/** @var EncryptionKey */
	private $encryptionKey;

	/**
	 * Creates a new Encryption Key. Should be generated only once and persisted safely.
	 *
	 * @return HiddenString
	 * @throws PhpVaultException
	 */
	public static function GenerateEncryptionKey(): HiddenString
	{
		try
		{
			$keyData	= KeyFactory::generateEncryptionKey()->getRawKeyMaterial();

			return new HiddenString(
				Hex::encode(
					Halite::HALITE_VERSION_KEYS . $keyData .
					sodium_crypto_generichash(
						Halite::HALITE_VERSION_KEYS . $keyData,
						'',
						SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
					)
				)
			);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * Creates a new encryption key and persists it into a file
	 *
	 * @param string $filename
	 * @throws PhpVaultException
	 */
	public static function GenerateEncryptionKeyFile(string $filename): void
	{
		try
		{
			$encryptionKey	= KeyFactory::generateEncryptionKey();
			if(!KeyFactory::save($encryptionKey, $filename))
			{
				throw new PhpVaultException('Could not save encryption key file');
			}
		}
		// @codeCoverageIgnoreStart
		catch (PhpVaultException $exception)
		{
			throw $exception;
		}
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * Factory: from HiddenString holding the encryption key
	 *
	 * @param HiddenString $encryptionKeyString
	 * @return PhpVault
	 * @throws PhpVaultException
	 */
	public static function FactoryFromString(HiddenString $encryptionKeyString): PhpVault
	{
		try
		{
			$encryptionKey	= KeyFactory::importEncryptionKey($encryptionKeyString);

			return new static($encryptionKey);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * Factory: from string containing full path to file holding the encryption key
	 *
	 * @param string $filename
	 * @return PhpVault
	 * @throws PhpVaultException
	 */
	public static function FactoryFromFile(string $filename): PhpVault
	{
		try
		{
			$encryptionKey	= KeyFactory::loadEncryptionKey($filename);

			return new static($encryptionKey);
		}
			// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * PhpVault constructor.
	 *
	 * @param EncryptionKey $encryptionKey
	 */
	protected function __construct(EncryptionKey $encryptionKey)
	{
			$this->encryptionKey	= $encryptionKey;
	}

	/**
	 * @param HiddenString $string
	 * @return string
	 * @throws PhpVaultException
	 */
	public function hash(HiddenString $string): string
	{
		try
		{
			return Password::hash($string, $this->encryptionKey);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * @param HiddenString $string
	 * @param string       $hash
	 * @return bool
	 * @throws PhpVaultException
	 */
	public function checkHash(HiddenString $string, string $hash): bool
	{
		try
		{
			return Password::verify($string, $hash, $this->encryptionKey);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * Encrypts $string
	 *
	 * @param HiddenString $string
	 * @return string
	 * @throws PhpVaultException
	 */
	public function lock(HiddenString $string): string
	{
		try
		{
			return Crypto::encrypt($string, $this->encryptionKey);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}

	/**
	 * Decrypts $encryptedString
	 *
	 * @param string $encryptedString
	 * @return HiddenString
	 * @throws PhpVaultException
	 */
	public function unlock(string $encryptedString): HiddenString
	{
		try
		{
			return Crypto::decrypt($encryptedString, $this->encryptionKey);
		}
		// @codeCoverageIgnoreStart
		catch (Throwable $exception)
		{
			throw new PhpVaultException($exception->getMessage(), $exception->getCode(), $exception);
		}
		// @codeCoverageIgnoreEnd
	}
}