<?php use Augusthur\Validation as Validate;

class NotificacionCtrl extends RMRController {

    protected $mediaTypes = ['json', 'view'];
    protected $properties = ['id', 'usuario_id'];

    public function queryModel($meth, $repr) {
        switch ($repr) {
            case 'view': return $this->session->getUser()->notificaciones()->withTrashed();
            case 'json': return $this->session->getUser()->notificaciones();
        }
    }

    public function executeListCtrl($paginator) {
        $notifis = $paginator->rows;
        $nav = $paginator->links;
        $this->render('usuario/notificaciones.twig', array('notificaciones' => $notifis->toArray(),
                                                           'nav' => $nav));
    }

    public function executeGetCtrl($notifi) {
        $this->notFound();
    }

    public function eliminar() {
        $usuario = $this->session->getUser();
        $usuario->notificaciones()->delete();
        $this->flash('success', 'Sus notificaciones han sido marcadas como leidas.');
        $this->redirect($this->request->getReferrer());
    }

    public static function createNotif($idUsu, $log) {
        $notif = new Notificacion();
        $notif->usuario_id = $idUsu;
        $notif->notificable()->associate($log);
        $notif->save();
        return $notif;
    }

}
