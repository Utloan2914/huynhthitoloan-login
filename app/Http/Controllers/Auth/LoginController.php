<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Models\User;
class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }
    protected function sendLoginResponse(Request $request)
    {
        $request->session()->regenerate();
        $sessionId = $request->session()->getId();
      
        $this->clearLoginAttempts($request);

        if ($response = $this->authenticated($request, $this->guard()->user())) {

            return $response;
        }
        $sessionId = $request->session()->getId();
        $user = $request->user();
        $user->last_session = $sessionId;
        $user->save();

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect()->intended($this->redirectPath());
    }
}
