<?php
// Clase PHP para subida de archivos directamente a Amazon AWS S3 class.simpleS3wrapper.php (2014-01-15 Javier Fuentes)

class formtoS3wrapper
{
    // (PHP 5 >= 5.1.2, PECL hash >= 1.1)
    private $bucket = null;
    private $key = null;
    private $secret = null;

    // Nombre del archivo que se sube en el formulario
    private $objectkey = 'tmp';
    // Tiempo máximo desde que se genera la URL de carga hasta que el usuario sube el archivo. Válido cualquier cosa que acepte strtotime()
    private $URLexpiration = '+1 hour';
    // Privacidad del objeto
    private $acl = 'private';
    // Por omisión, archivo de subida máximo de 5 Gb (máximo que permite S3)
    private $content_length_range = 5368709120;
    // OPCIONAL: uploadpath puede pasarse a setOptions() para que la carpeta de subida esté protegida y no pueda cambiarse
    private $uploadpath = '';
    // "Some versions of the Adobe Flash Player do not properly handle HTTP responses that have an empty body.
    // To configure POST to return a response that does not have an empty body, set success_action_status to 201.
    // When set, Amazon S3 returns an XML document with a 201 status code."
    // http://docs.amazonwebservices.com/AmazonS3/latest/dev/HTTPPOSTFlash.html
    private $success_action_status = '201';
    private $success_action_redirect = '';

    private function doBasicChecking()
    {
        if (!empty($this->uploadpath))
        {
            if (stristr($this->objectkey, $this->uploadpath) === false) throw new Exception('uploadpath must be part of objectkey');
        }
    }

    // hash_hmac Generate a keyed hash value using the HMAC method
    // based on: http://www.php.net/manual/en/function.sha1.php#39492
    private function hash_hmac($algo, $data, $key, $raw_output = false)
    {
        $blocksize = 64;
        if (strlen($key) > $blocksize)
            $key = pack('H*', $algo($key));

        $key = str_pad($key, $blocksize, chr(0x00));
        $ipad = str_repeat(chr(0x36), $blocksize);
        $opad = str_repeat(chr(0x5c), $blocksize);
        $hmac = pack('H*', $algo(($key^$opad) . pack('H*', $algo(($key^$ipad) . $data))));

        return $raw_output ? $hmac : bin2hex($hmac);
    }

    public function getInputFields()
    {
        $this->doBasicChecking();

        $str = '';

        $str .= '<input type="hidden" name="key" value="'.$this->objectkey.'">';
        $str .= '<input type="hidden" name="AWSAccessKeyId" value="'.$this->key.'">';
        $str .= '<input type="hidden" name="acl" value="'.$this->acl.'">';
        $str .= '<input type="hidden" name="success_action_redirect" value="'.$this->success_action_redirect.'">';
        $str .= '<input type="hidden" name="success_action_status" value="'.$this->success_action_status.'">';
        $str .= '<input type="hidden" name="policy" value="'.$this->getPolicy().'">';
        $str .= '<input type="hidden" name="signature" value="'.$this->getSignature().'">';

        return $str;

    }

    // Obtiene la policy
    public function getPolicy(){
        $this->doBasicChecking();

        return base64_encode(json_encode(array(
            // ISO 8601 - date('c'); generates uncompatible date, so better do it manually
            'expiration' => date('Y-m-d\TH:i:s.000\Z', strtotime($this->URLexpiration)),
            'conditions' => array(
                array('bucket' => $this->bucket),
                array('acl' => $this->acl),
                array('success_action_redirect' => $this->success_action_redirect),
                array('success_action_status' => $this->success_action_status),
                array('content-length-range', 0, $this->content_length_range),
                array('starts-with', '$key', $this->uploadpath)
            )
        )));
    }

    public function getSignature()
    {
        return base64_encode($this->hash_hmac('sha1', $this->getPolicy(), $this->secret, true));
    }

    public function setOptions($opts)
    {
        if ($opts['key']) $this->key = $opts['key'];
        if ($opts['secret']) $this->secret = $opts['secret'];
        if ($opts['bucket']) $this->bucket = $opts['bucket'];
        if ($opts['acl']) $this->acl = $opts['acl'];
        if ($opts['success_action_redirect']) $this->success_action_redirect = $opts['success_action_redirect'];
        if ($opts['success_action_status']) $this->success_action_status = $opts['success_action_status'];
        if ($opts['content-length-range']) $this->content_length_range = $opts['content-length-range'];
        if ($opts['uploadpath']) $this->uploadpath = $opts['uploadpath'];
        if ($opts['urlexpiration']) $this->URLexpiration = $opts['urlexpiration'];
        if ($opts['objectkey']) $this->objectkey = $opts['objectkey'];

        return true;
    }
}