@echo off
REM Runs the Phishing Email Analyser self-tests using the JavaScript engine
REM built into Windows. No software needs to be installed.
cscript //nologo "%~dp0run-selftest.js"
exit /b %ERRORLEVEL%
