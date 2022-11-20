<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => ['required', 'string'],
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'confirmed']
        ]);

        $fields['password'] = bcrypt($fields['password']);

        $user = User::create($fields);

        $token = $user->createToken('abcdefghijklmnopqrstuvwxyz')->plainTextToken;

        return response(['user' => $user, 'token' => $token], 201);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => ['required'],
            'password' => ['required']
        ]);

        // Check Email and Password
        $user = User::where('email', $fields['email'])->first();
        if (!$user || !Hash::check($fields['password'], $user['password'])) {
            return response(['message' => 'Bad Credentials'], 401);
        }

        $token = $user->createToken('abcdefghijklmnopqrstuvwxyz')->plainTextToken;

        return response(['user' => $user, 'token' => $token], 200);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return ['message' => 'Logged out'];
    }
}
