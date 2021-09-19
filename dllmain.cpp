/*
* MIT License
*
* Copyright (c) 2021 Eternal
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/


#include <Windows.h>
#include "CurlDefinitions.h"
#include "scanner.h"
#include "xorstr.hpp"
#include "MinHook.h"
#include <regex>
#include <cstdarg>
//Original curl_easy_setopt routine which will be used to set up curl and continue normal execution
auto (*_curl_easy_setopt)(CURL* cURL, uintptr_t option, ...) -> CURLcode;

//This routine is used for setting up curl. we will be hijacking this to change the values.
auto Hijacked_curl_easy_setopt(CURL* cURL, uintptr_t option, va_list data) -> CURLcode// was PVOID
{

    switch (option)
    {

       
    case CURLOPT_NOPROXY:
        //To disable proxy
        return _curl_easy_setopt(cURL, option, E(""));
        break;
        
    case CURLOPT_SSL_VERIFYPEER:
        //The application has called curl_easy_setopt with verify peer option to set up the peer check

        //change verify peer to 0 (off) or it will error
        return _curl_easy_setopt(cURL, option, 0);
        break;
    case CURLOPT_SSL_VERIFYHOST:
        //The application has called curl_easy_setopt with verify host option to set up the host check

        //change verify host to 0 (off) or it will error
        return _curl_easy_setopt(cURL, option, 0);
        break;
    case CURLOPT_PINNEDPUBLICKEY:
        //The application has called curl_easy_setopt with public key pinning option to set up ssl pinning

        //return ok because we want to disable ssl pinning so we can use custom urls
        return CURLcode::CURLE_OK;
        break;
        
    case CURLOPT_URL:
        std::regex Host("(.*).ol.epicgames.com");
        std::string FNhost = "storm1.stormzyglitches.repl.co";
        std::string url = data;
        if (std::regex_search(data, std::regex("/fortnite/api/cloudstorage/system"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        else if (std::regex_search(data, std::regex("/fortnite/api/game/v2/profile"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        else if (std::regex_search(data, std::regex("/content/api/pages/fortnite-game"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        else if (std::regex_search(data, std::regex("/fortnite/api/v2/versioncheck"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        else if (std::regex_search(data, std::regex("/affiliate/api/public/affiliates/slug"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        else if (std::regex_search(data, std::regex("/socialban/api/public/v1"))) {
            url = std::regex_replace(data, Host, FNhost);
        }
        return _curl_easy_setopt(cURL, option, url.c_str());
        break;
    }

    //if the option is not of our interest, we will continue normal execution.
    return _curl_easy_setopt(cURL, option, data);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        //initialize minhook
        auto status = MH_Initialize();
        if (status != MH_OK)
        {
            return FALSE;
        }

        //pattern scan the functions we're going to hook
        auto CurlEasyOpt_ = sigscan(E("89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9"));

        if (!CurlEasyOpt_)
        {
            //Pattern Not Found
            MessageBoxA(0, E("Failed To Find curl_easy_setopt Function!"), E("CSM Fatal Error!"), MB_ICONERROR);
            return FALSE;
        }

        //create hook to the functions
        MH_CreateHook((void*)CurlEasyOpt_, Hijacked_curl_easy_setopt, (void**)&_curl_easy_setopt);

        //enable the hook
        status = MH_EnableHook((void*)CurlEasyOpt_);
        if (status != MH_OK)
        {
            return FALSE;
        }

    }
    return TRUE;
}   