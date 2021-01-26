<?php
/**
 * RefreshToken
 */
namespace XuDongYss\JWT;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;

class RefreshToken{
	protected $encryptionKey;
	protected $identifier = '';
	protected $expires = '+1 month';
	protected $refreshToken = [];
	
	/**
	 * 初始化
	 * @param string 	$encryptionKey 加密 key
	 * @param string 	$expires
	 */
	public function __construct($encryptionKey, $expires = '') {
		$this->encryptionKey = $encryptionKey;
		if($expires) $this->expires = $expires;
	}
	
	/**
	 * 创建
	 * @param int 		$uid
	 * @param string 	$accessTokenId
	 * @return string
	 */
	public function create($uid, $accessTokenId) {
		$this->refreshToken = [
			'refresh_token_id'=> $this->generateUniqueIdentifier(),
			'access_token_id'=> $accessTokenId,
			'uid'=> $uid,
			'expire_time'=> strtotime($this->expires),
		];
		$refreshTokenJson = json_encode($this->refreshToken);
		
		try{
			return Crypto::encryptWithPassword($refreshTokenJson, $this->encryptionKey);
		}catch(EnvironmentIsBrokenException $e) {
			throw new \Exception('RefreshToken 生成失败');
		}catch(\TypeError $e) {
			throw new \Exception('RefreshToken 生成失败');
		}
	}
	
	/**
	 * 校验
	 * @param string 		$refreshTokenString
	 * @throws \Exception
	 */
	public function validating($refreshTokenString) {
		try{
			$refreshTokenJson = Crypto::decryptWithPassword($refreshTokenString, $this->encryptionKey);
			$refreshToken = json_decode($refreshTokenJson, true);
			if($refreshToken) {
				$this->refreshToken = $refreshToken;
				$this->validExpireTime();
				
				return $this->refreshToken;
			}
			
			throw new \Exception('RefreshToken 错误');
		}catch(EnvironmentIsBrokenException $e) {
			throw new \Exception('RefreshToken 错误');
		}catch(\TypeError $e) {
			throw new \Exception('RefreshToken 错误');
		}catch(\Exception $e) {
			throw new \Exception($e->getMessage());
		}
	}
	
	public function getClaim($key) {
		return $this->refreshToken[$key];
	}
	
	/**
	 * 是否过期
	 * @throws \Exception
	 * @return boolean
	 */
	protected function validExpireTime() {
		if($this->refreshToken['expire_time'] < time()) throw new \Exception('RefreshToken 已过期');
		
		return true;
	}
	
	protected function generateUniqueIdentifier($length = 40) {
		return \bin2hex(\random_bytes($length));
	}
}