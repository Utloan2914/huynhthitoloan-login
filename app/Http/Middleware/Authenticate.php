<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Support\Facades\Auth;

class Authenticate extends Middleware
{
    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function redirectTo($request)
    {
        if (!$request->expectsJson()) {
            return route('login');
        }
    }
    protected function authenticate($request, array $guards)
    {

        if (empty($guards)) {
            $guards = [null];
        }

        foreach ($guards as $guard) {
            if ($this->auth->guard($guard)->check()) {
                 //Check login
                /*
                - Lấy sesion hiện tại (sessionId)
                - So sánh với sessionId trong bảng users
                --> Nếu khác nhau: Xử lý logout (Kèm theo message)
                --> Nếu giống nhau --> Bỏ qua
                */
              $checkDevice =  $this->checkDevice($request);
              if(!$checkDevice){
                return redirect(route('login'));
              }
                return $this->auth->shouldUse($guard);
            }
        }

        $this->unauthenticated($request, $guards);
    }
    private function checkDevice($request)
    {
        $sessionId = $request->sessionId()->getId();
        $user = $request->user();
        $lastSessionId = $user->last_session;
        if ($lastSessionId !== $sessionId) {
            Auth::logout();
            return false;
        }
        return true;
    }
}
