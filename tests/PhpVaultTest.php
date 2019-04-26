<?php
namespace THansen\PhpVault;

use Exception;
use Generator;
use IntlChar;
use ParagonIE\HiddenString\HiddenString;
use \THansen\PhpVault\Exception\PhpVaultException;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Class PhpVaultTest
 * @package THansen\PhpVault
 */
class PhpVaultTest extends TestCase
{
	public static $HashTestIterations		= 10; // Tested up to 100000 iterations
	public static $LockUnlockTestIterations	= 50; // Tested up to 100000 iterations

	/**
	 * Generates random strings to be tested.
	 * Based on https://stackoverflow.com/a/42535566
	 *
	 * @return string
	 * @throws Exception
	 */
	protected function randomString(): string
	{
		$return	= '';
		$length	= random_int(2, 100);

		for ($i = 0; $i < $length; $i++)
		{
			$codePoint	= mt_rand(0x80, 0xffff);
			$char		= IntlChar::chr($codePoint);
			if ($char !== null && IntlChar::isprint($char))
			{
				$return	.= $char;
			}
			else
			{
				$i--;
			}
		}

		return $return;
	}

	/**
	 * @return Generator
	 * @throws Exception
	 */
	public function hashDataProvider(): Generator
	{
		$encryptionKey	= PhpVault::GenerateEncryptionKey();
		$phpVault		= PhpVault::FactoryFromString($encryptionKey);

		for ($i = 0; $i < self::$HashTestIterations; $i++)
		{
			yield [$phpVault, new HiddenString($this->randomString())];
		}
	}

	/**
	 * @return Generator
	 * @throws Exception
	 */
	public function vaultDataProvider(): Generator
	{
		$encryptionKey	= PhpVault::GenerateEncryptionKey();
		$phpVault		= PhpVault::FactoryFromString($encryptionKey);

		for ($i = 0; $i < self::$LockUnlockTestIterations; $i++)
		{
			yield [$phpVault, new HiddenString($this->randomString())];
		}
	}

	/**
	 * @throws PhpVaultException
	 */
	public function testGenerateEncryptionKey(): void
	{
		$encryptionKey	= PhpVault::GenerateEncryptionKey();
		self::assertIsString($encryptionKey->getString());
	}

	/**
	 * @throws PhpVaultException
	 */
	public function testGenerateEncryptionKeyFile(): void
	{
		$filename	= sys_get_temp_dir().'/'.uniqid('PhpVaultTest', true).'.key';
		PhpVault::GenerateEncryptionKeyFile($filename);
		self::assertFileExists($filename);
		try
		{
			PhpVault::FactoryFromFile($filename);
			self::assertTrue(true);
		}
		catch (Throwable $exception)
		{
			self::assertTrue(false);
		}
	}

	/**
	 * @dataProvider hashDataProvider
	 * @param PhpVault     $phpVault
	 * @param HiddenString $string $string
	 * @throws PhpVaultException
	 */
	public function testHash(PhpVault $phpVault, HiddenString $string): void
	{
		$hash	= $phpVault->hash($string);
		static::assertTrue($phpVault->checkHash($string, $hash));
	}

	/**
	 * @throws PhpVaultException
	 */
	public function testFactoryFromString()
	{
		$encryptionKey	= PhpVault::GenerateEncryptionKey();
		$phpVault		= PhpVault::FactoryFromString($encryptionKey);
		self::assertTrue($phpVault instanceof PhpVault);
	}

	/**
	 * @dataProvider vaultDataProvider
	 * @param PhpVault     $phpVault
	 * @param HiddenString $string
	 * @throws PhpVaultException
	 */
	public function testLockUnlock(PhpVault $phpVault, HiddenString $string)
	{
		static::assertEquals($string->getString(), $phpVault->unlock($phpVault->lock($string)));
	}
}
