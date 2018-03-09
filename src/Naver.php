<?php

namespace Deminoth\OAuth2\Client\Provider;

use Guzzle\Http\Exception\BadResponseException;
use Guzzle\Service\Client as GuzzleClient;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Exception\IDPException;
use Fontis\Mage1LogAdapter\Psr3;
use Zend_Log;

class Naver extends AbstractProvider
{
    /**
     * @var Psr3
     */
    protected $logger;

    public function __construct($options  = [])
    {
        parent::__construct($options);
        $this->logger = new Psr3('sociallogin_requests.log', Zend_Log::DEBUG);
    }
    
    public function urlAuthorize() 
    {
        return 'https://nid.naver.com/oauth2.0/authorize';
    }

    public function urlAccessToken() 
    {
        return 'https://nid.naver.com/oauth2.0/token';
    }

    public function urlUserDetails(AccessToken $token) 
    {
        return 'https://apis.naver.com/nidlogin/nid/getUserProfile.xml';
    }

    public function getUserDetails(AccessToken $token, $force = false)
    {
        $xml_response = $this->fetchUserDetails($token);

        return $this->userDetails($xml_response, $token);
    }

    public function getUserUid(AccessToken $token, $force = false)
    {
        $xml_response = $this->fetchUserDetails($token, $force);

        return $this->userUid($xml_response, $token);
    }

    public function getUserEmail(AccessToken $token, $force = false)
    {
        $xml_response = $this->fetchUserDetails($token, $force);

        return $this->userEmail($xml_response, $token);
    }

    public function getUserScreenName(AccessToken $token, $force = false)
    {
        $xml_response = $this->fetchUserDetails($token, $force);

        return $this->userScreenName($xml_response, $token);
    }

    public function userDetails($response, AccessToken $token)
    {

        $user = new User;

        $user->uid = (string) $response->response->enc_id;
        $user->nickname = (string) $response->response->nickname;
        $user->name = (string) $response->response->nickname;
        $user->imageUrl = (string) $response->response->profile_image;
        $user->email = (string) $response->response->email;
      
        return $user;

    }

    public function userUid($response, AccessToken $token)
    {
        return (string) $response->response->enc_id;
    }

    public function userEmail($response, AccessToken $token)
    {
        return (string) $response->response->email;
    }

    public function userScreenName($response, AccessToken $token)
    {
        return (string) $response->response->nickname;
    }

    protected function fetchUserDetails(AccessToken $token, $force = true)
    {

        $url = $this->urlUserDetails($token);

        try {

            $client = new GuzzleClient();
            $request = $client->get($url, array('Authorization'=>'Bearer '.$token));
            $response = $request->send();
            $xml_response = $response->xml();

        } catch (BadResponseException $e) {

            $raw_response = explode("\n", $e->getResponse());
            throw new IDPException(end($raw_response));

        }
        
        return $xml_response;
    }

    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        if (is_string($grant)) {
            // PascalCase the grant. E.g: 'authorization_code' becomes 'AuthorizationCode'
            $className = str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $grant)));
            $grant = 'League\\OAuth2\\Client\\Grant\\'.$className;
            if (! class_exists($grant)) {
                throw new \InvalidArgumentException('Unknown grant "'.$grant.'"');
            }
            $grant = new $grant();
        } elseif (! $grant instanceof GrantInterface) {
            $message = get_class($grant).' is not an instance of League\OAuth2\Client\Grant\GrantInterface';
            throw new \InvalidArgumentException($message);
        }

        $defaultParams = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'grant_type'    => $grant,
        ];

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            switch (strtoupper($this->method)) {
                case 'GET':
                    // @codeCoverageIgnoreStart
                    // No providers included with this library use get but 3rd parties may
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
                    $request = $client->get(null, $this->getHeaders(), $requestParams)->send();
                    $response = $request->getBody();
                    break;
                // @codeCoverageIgnoreEnd
                case 'POST':
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken());
                    $request = $client->post(null, $this->getHeaders(), $requestParams)->send();
                    $response = $request->getBody();
                    break;
                // @codeCoverageIgnoreStart
                default:
                    throw new \InvalidArgumentException('Neither GET nor POST is specified for request');
                // @codeCoverageIgnoreEnd
            }
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse()->getBody();
            // @codeCoverageIgnoreEnd
        }

        $result = $this->prepareResponse($response);

        try {
            if (isset($request)) {
                $url = $request->getEffectiveUrl();
                $this->logger->log(
                    Zend_Log::INFO,
                    "Request URL: $url, Params:\n" . var_export($requestParams, true) . "\nResult: "
                    . var_export($result, true)
                );
            }
        } catch (Exception $e) {
            $this->logger->log($e->getMessage());
        }
        if (isset($result['error']) && ! empty($result['error'])) {
            // @codeCoverageIgnoreStart
            throw new IDPException($result);
            // @codeCoverageIgnoreEnd
        }

        $result = $this->prepareAccessTokenResult($result);

        return $grant->handleResponse($result);
    }
}
