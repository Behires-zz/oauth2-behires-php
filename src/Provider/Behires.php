<?php
namespace League\OAuth2\Client\Provider;

use GuzzleHttp\Client as HttpClient;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class Behires extends AbstractProvider
{
    use BearerAuthorizationTrait;

    private $dev = false;

    /**
     * Default scope
     *
     * @var array
     */
    public $defaultScopes = ['basic'];

    /**
     * Behires constructor.
     *
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options, array $collaborators = [])
    {
        $collaborators['httpClient'] = new HttpClient([
            'timeout' => 30,
            'verify' => __DIR__ . '/../cert/COMODORSACertificationAuthority.pem'
        ]);

        parent::__construct($options, $collaborators);
    }

    /**
     * Allow to use the dev api endpoint
     *
     * @return void
     */
    public function activateDevelopment()
    {
        $this->dev = true;
    }

    /**
     * Get the string used to separate scopes.
     *
     * @return string
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->buildBaseUrl() . '/oauth/authorize';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->buildBaseUrl() . '/oauth/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->buildBaseUrl() . '/v1/users/self';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return $this->defaultScopes;
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if(isset($data['errors'])) {
            throw new IdentityProviderException(
                json_encode($data['errors']),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        // TODO: Implement createResourceOwner() method.
    }

    /**
     * Build the base domain
     *
     * @return string
     */
    private function buildBaseUrl()
    {
        if($this->dev) {
            return 'https://dev-api.behires.com';
        }

        return 'https://api.behires.com';
    }
}