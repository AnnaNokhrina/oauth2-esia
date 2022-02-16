<?php

namespace Ekapusta\OAuth2Esia\Token;

use Ekapusta\OAuth2Esia\Interfaces\Token\ScopedTokenInterface;
use InvalidArgumentException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Client\Token\AccessToken;

class EsiaAccessToken extends AccessToken implements ScopedTokenInterface
{
    private $parsedToken;

    public function __construct(array $options, $publicKeyPath = null, Signer $signer = null)
    {
        parent::__construct($options);

        /** @var Plain parsedToken */
        $this->parsedToken = (new Parser(new JoseEncoder()))->parse($this->accessToken);
        $this->resourceOwnerId = $this->parsedToken->claims()->get(name: 'urn:esia:sbj_id');


        $validatorToken = new Validator();
        if (!$validatorToken->validate(token: $this->parsedToken)) {
            throw new InvalidArgumentException(message: 'Access token is invalid: ' . var_export(value: $options, return: true));
        }

        $key = InMemory::file(path: $publicKeyPath);

        $verifyToken = false;
        if ($this->parsedToken->headers()->get(name: 'alg') === $signer->algorithmId()) {
            $verifyToken = $signer->verify(
                expected: $this->parsedToken->signature()->hash(),
                payload: $this->parsedToken->payload(),
                key: $key,
            );
        }

        if (!$verifyToken) {
            throw new InvalidArgumentException(message: 'Access token can not be verified: ' . var_export(value: $options, return: true));
        }
    }

    public function getScopes(): array
    {
        $scopes = [];
        foreach (explode(separator: ' ', string: $this->parsedToken->claims()->get(name: 'scope', default: '')) as $scope) {
            $scopes[] = parse_url(url: $scope, component: PHP_URL_PATH);
        }

        return $scopes;
    }
}
