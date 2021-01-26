<?php
/**
 * RefreshToken
 */
namespace XuDongYss\JWT;

use Defuse\Crypto\Crypto;

class RefreshToken{
	protected $encryptionKey;
	protected $identifier = '';
	protected $expires = '+1 month';
	
	/**
	 * 初始化
	 * @param string 	$encryptionKey 加密 key
	 * @param string 	$expires
	 */
	public function __construct($encryptionKey, $expires = '') {
		if($expires) $this->expires = $expires;
	}
	
	public function create($uid, $accessTokenId) {
		$this->identifier = $this->generateUniqueIdentifier();
		$_data = [
			'refresh_token_id'=> $this->identifier,
			'access_token_id'=> $accessTokenId,
			'uid'=> $uid,
			'expire_time'=> strtotime($this->expires),
		];
		$plaintext = json_encode($_data);
		
		return Crypto::encryptWithPassword($plaintext, $this->encryptionKey);
	}
	
	protected function generateUniqueIdentifier($length = 40) {
		return \bin2hex(\random_bytes($length));
	}
	
	public function getIdentifier() {
		return $this->identifier;
	}
}