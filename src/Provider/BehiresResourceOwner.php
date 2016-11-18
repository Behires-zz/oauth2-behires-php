<?php
namespace League\OAuth2\Client\Provider;


use League\OAuth2\Client\Tool\ArrayAccessorTrait;

class BehiresResourceOwner extends GenericResourceOwner
{
    use ArrayAccessorTrait;

    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param array  $response
     */
    public function __construct(array $response = array())
    {
        $this->response = $response;
    }

    /**
     * @return array
     */
    public function getResponse()
    {
        return $this->response;
    }
}