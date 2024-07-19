#!/usr/bin/env python3
"""test module"""
from requests import post, get, delete, put
BASE_URL = 'http://localhost:5000'
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    """register_user test"""
    data = {"email": email, "password": password}
    res = post(f'{BASE_URL}/users', data=data)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """log_in_wrong_password test"""
    data = {"email": email, "password": password}
    res = post(f'{BASE_URL}/sessions', data=data)
    assert res.status_code == 401


def log_in(email: str, password: str) -> str:
    """log_in test"""
    data = {"email": email, "password": password}
    res = post(f'{BASE_URL}/sessions', data=data)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "logged in"}
    return res.cookies.get("session_id")


def profile_unlogged() -> None:
    """profile_unlogged test"""
    cookies = {"session_id": ""}
    res = get(f'{BASE_URL}/profile', cookies=cookies)
    assert res.status_code == 403


def profile_logged(session_id: str) -> None:
    """profile_logged test"""
    cookies = {"session_id": session_id}
    res = get(f'{BASE_URL}/profile', cookies=cookies)
    assert res.status_code == 200
    assert res.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    """log_out test"""
    cookies = {"session_id": session_id}
    res = delete(f'{BASE_URL}/sessions', cookies=cookies)
    assert res.status_code == 200
    assert res.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """reset_password_token test"""
    data = {"email": email}
    res = post(f'{BASE_URL}/reset_password', data=data)
    reset_token = res.json().get("reset_token")
    assert res.status_code == 200
    assert res.json() == {"email": email, "reset_token": reset_token}
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """update_password test"""
    data = {"email": email, "reset_token": reset_token,
            "new_password": new_password}
    res = put(f'{BASE_URL}/reset_password', data=data)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
