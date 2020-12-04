<?php
namespace XuDongYss\JWT;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;

class Token{
    /**
     * 过期时间
     * +1 year(s) month(s) day(s) hour(s) minute(s) second(s)
     */
    protected $iss = '';
    protected $aud = '';
    protected $expires = '+1 hour';
    protected $privateKey = '';
    protected $publicKey = '';
    
    protected Configuration $config;
    
    /**
     * 初始化
     * @param string 	$privateKey		私钥
     * @param string 	$publicKey		公钥
     * @param string 	$iss			
     * @param string 	$aud
     * @param string 	$expires		过期时间
     */
    public function __construct($privateKey, $publicKey, $iss = '', $aud = '', $expires = '') {
    	$this->privateKey = $privateKey;
    	$this->publicKey = $publicKey;
    	
    	$this->iss = $iss;
    	$this->aud = $aud;
    	if($expires) $this->expires = $expires;
    	
    	$privateKey = InMemory::plainText($this->handlePrivateKey($this->privateKey));
    	$publicKey = InMemory::plainText($this->handlePublicKey($this->publicKey));
    	
    	$this->config = Configuration::forAsymmetricSigner(new Sha256(), $privateKey, $publicKey);
    }
    
    /**
     * 创建 Token
     * @param int 		$uid	用户ID
     * @return string
     */
    public function create($uid) {
		$now = new \DateTimeImmutable();
		$builder = $this->config->builder();
		if($this->iss) $builder->issuedBy($this->iss);
		if($this->aud) $builder->permittedFor($this->aud);
		$builder->identifiedBy(bin2hex(random_bytes(5)));
		$builder->issuedAt($now);
		$builder->expiresAt($now->modify($this->expires));
		$builder->withClaim('uid', $uid);
		$token = $builder->getToken($this->config->signer(), $this->config->signingKey());
    
		return $token->toString();
    }
    
    /**
     * 验证
     * @param string 		$tokenString
     * @throws \Exception
     * @return boolean
     */
    public function validating($tokenString, $jti = false) {
    	$token = $this->config->parser()->parse($tokenString);
    	
    	$this->setValidationConstraints($jti);
    	$constraints = $this->config->validationConstraints();
    	
    	if(!$this->config->validator()->validate($token, ...$constraints)) {
    		throw new \Exception('Token 错误');
    	}
    	
    	return true;
    }
    
    /**
     * 设置验证器
     */
    protected function setValidationConstraints($jti = false) {
    	/* 设置验证器 */
    	$validationConstraints = [
    		new SignedWith($this->config->signer(), $this->config->verificationKey()),	//验证签名
    		new ValidAt(new SystemClock(new \DateTimeZone('Asia/Shanghai'))),			//验证时间：可用时间、过期时间
    	];
    	/* 验证 jti */
    	if($jti !== false) $validationConstraints[] = new IdentifiedBy($jti);
    	if($this->iss) $validationConstraints[] = new IssuedBy($this->iss);
    	if($this->aud) $validationConstraints[] = new PermittedFor($this->aud);
    	
    	$this->config->setValidationConstraints(...$validationConstraints);
    }
    
    /**
     * 处理私钥
     * @param string	$privateKey	纯字符串（一整行，无换行）
     * @return string
     */
    public function handlePrivateKey($privateKey) {
    	return "-----BEGIN RSA PRIVATE KEY-----\n".wordwrap($privateKey, 64, "\n", true)."\n-----END RSA PRIVATE KEY-----";
    }
    
    /**
     * 处理公钥
     * @param string	$publicKey	纯字符串（一整行，无换行）
     * @return string
     */
    public function handlePublicKey($publicKey) {
    	return "-----BEGIN PUBLIC KEY-----\n".wordwrap($publicKey, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }
}