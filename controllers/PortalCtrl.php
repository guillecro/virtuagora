<?php use Augusthur\Validation as Validate;

class PortalCtrl extends Controller {

    public function verIndex() {
        if ($this->session->check()) {
            $this->render('portal/inicio.twig');
        } else {
            $this->render('portal/introduccion.twig');
        }
    }

    public function verPortal() {
        $this->render('portal/contenidos.twig');
    }

    public function verLogin() {
        $this->render('registro/login-static.twig');
    }

    public function verTos() {
        $tos = Ajuste::where('key', 'tos')->firstOrFail();
        $this->render('portal/tos.twig', ['tos' => $tos->toArray()]);
    }
    
    public function verCertificar() {
        if ($this->session->hasRole('vrf')) {
            throw new BearableException('Tu cuenta ya está verificada.');
        }
        $this->render('portal/certificar.twig');
    }
    
    public function certificar() {
        $req = $this->request;
        $ch = curl_init();
        $url = 'https://guarani.frsf.utn.edu.ar/v291/validador_certificados/validar';
        $fields = 'codigo_valid=' . $req->post('codigo') . '&recaptcha_response_field=' .
            urlEncode($req->post('captcha')) . '&recaptcha_challenge_field=' .
            $req->post('challenge') . '&validar=Validar';
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
        $html = curl_exec($ch);
        curl_close($ch);
        $match = array();
        $target = '~La Facultad Regional Santa Fe certifica que (.*?) con legajo n\\\\u00famero (.*?), DNI (.*?), ' .
                    'de origen Argentino, se encuentra actualmente regular en la carrera de (.*?), plan~';
        if (preg_match($target, $html, $match) === 1) {
            $certUsr = Usuario::where('lu', $match[2])->orWhere('dni', $match[3])->first();
            if (!is_null($certUsr)) {
                throw new TurnbackException('Esta persona ya tiene su cuenta certificada.');
            }
            $usuario = $this->session->getUser();
            $nombreReal = explode(' ', iconv('UTF-8', 'ASCII//TRANSLIT', substr($match[1], 10)));
            $nombreUser = explode(' ', iconv('UTF-8', 'ASCII//TRANSLIT', strtoupper($usuario->nombre)));
            $apelliUser = explode(' ', iconv('UTF-8', 'ASCII//TRANSLIT', strtoupper($usuario->apellido)));
            $nombreOk = count(array_intersect($nombreUser, $nombreReal)) > 0;
            $nombreOk &= count(array_intersect($apelliUser, $nombreReal)) > 0;
            if (!$nombreOk) {
                throw new TurnbackException('Tu nombre no coincide con: '.substr($match[1], 10).'.');
            }
            $usuario->lu = $match[2];
            $usuario->dni = $match[3];
            $usuario->carrera = $match[4];
            $usuario->verified_at = Carbon\Carbon::now();
            $usuario->save();
            $this->flash('success', '¡Felicitaciones! Tu cuenta ya está verificada.');
            $this->redirectTo('shwPortal');
            //var_dump(substr($match[1], 10), $match[2], $match[3], $match[4]);
        } else {
            throw new TurnbackException('La validación falló. Comprobá el código de validación y el captcha.');
        }
    }

    public function login() {
        $vdt = new Validate\Validator();
        $vdt->addRule('email', new Validate\Rule\Email())
            ->addRule('email', new Validate\Rule\MaxLength(128))
            ->addRule('password', new Validate\Rule\MaxLength(128));
        $req = $this->request;
        if ($vdt->validate($req->post()) && $this->session->login($vdt->getData('email'), $vdt->getData('password'))) {
            $this->redirectTo('shwPortal');
        } else {
            $this->flash('errors', array('Datos de ingreso incorrectos. Por favor vuelva a intentarlo.'));
            $this->redirectTo('shwLogin');
        }
    }

    public function logout() {
        $this->session->logout();
        $this->redirectTo('shwIndex');
    }

    public function verRegistrar() {
        $this->render('registro/registro.twig');
    }

    public function registrar() {
        $vdt = new Validate\Validator();
        $vdt->addRule('nombre', new Validate\Rule\Alpha(array(' ')))
            ->addRule('nombre', new Validate\Rule\MinLength(1))
            ->addRule('nombre', new Validate\Rule\MaxLength(32))
            ->addRule('apellido', new Validate\Rule\Alpha(array(' ')))
            ->addRule('apellido', new Validate\Rule\MinLength(1))
            ->addRule('apellido', new Validate\Rule\MaxLength(32))
            ->addRule('password', new Validate\Rule\MinLength(8))
            ->addRule('password', new Validate\Rule\MaxLength(128))
            ->addRule('password', new Validate\Rule\Matches('password2'))
            ->addRule('email', new Validate\Rule\Email())
            ->addRule('email', new Validate\Rule\MaxLength(128))
            ->addRule('email', new Validate\Rule\Unique('usuarios'))
            ->addRule('email', new Validate\Rule\Unique('preusuarios'))
            ->addFilter('email', 'strtolower')
            ->addFilter('email', 'trim');
        if ($this->getMode() != 'testing') {
            $phrase = isset($this->flashData()['captcha'])? $this->flashData()['captcha']: null;
            $vdt->addRule('captcha', new Validate\Rule\Equal($phrase));
        }
        $req = $this->request;
        if (!$vdt->validate($req->post())) {
            throw new TurnbackException($vdt->getErrors());
        }
        $preuser = new Preusuario;
        $preuser->email = $vdt->getData('email');
        $preuser->password = password_hash($vdt->getData('password'), PASSWORD_DEFAULT);
        $preuser->nombre = $vdt->getData('nombre');
        $preuser->apellido = $vdt->getData('apellido');
        $preuser->emailed_token = bin2hex(openssl_random_pseudo_bytes(16));
        $preuser->save();
        if ($this->getMode() != 'testing') {
            $to = $preuser->email;
            $subject = 'Confirma tu registro en Virtuagora';
            $message = 'Hola, te registraste en virtuagora. Entra a este link para confirmar tu email: ' . $req->getUrl() .
                       $this->urlFor('runValidUsuario', array('idUsu' => $preuser->id, 'token' => $preuser->emailed_token));
            mail($to, $subject, $message);
        }
        $this->render('registro/registro-exito.twig', array('email' => $preuser->email));
    }

    public function verificarEmail($idPre, $token) {
        $vdt = new Validate\QuickValidator(array($this, 'notFound'));
        $vdt->test($idPre, new Validate\Rule\NumNatural());
        $vdt->test($token, new Validate\Rule\AlphaNumeric());
        $vdt->test($token, new Validate\Rule\ExactLength(32));
        $preuser = Preusuario::findOrFail($idPre);
        if ($token == $preuser->emailed_token) {
            $usuario = new Usuario;
            $usuario->email = $preuser->email;
            $usuario->password = $preuser->password;
            $usuario->nombre = $preuser->nombre;
            $usuario->apellido = $preuser->apellido;
            $usuario->puntos = 0;
            $usuario->suspendido = false;
            $usuario->es_funcionario = false;
            $usuario->es_jefe = false;
            $usuario->img_tipo = 1;
            $usuario->img_hash = md5($preuser->email);
            $usuario->save();
            $preuser->delete();
            $this->render('registro/validar-correo.twig', array('usuarioValido' => true,
                                                                'email' => $usuario->email));
        } else {
            $this->render('registro/validar-correo.twig', array('usuarioValido' => false));
        }
    }

}
