# Script to determine Mac OS version.
# fatemabw, 2016

@load base/protocols/http
@load base/frameworks/software

module MACOS;

    export {
        redef enum Software::Type += {
        ## Identifier for Macintosh operating system versions
             MACINTOSH,
        };

        type Software::name_and_version: record {
                name   : string;
                version: Software::Version;
        };

        global arr1: string_vec;
        global arr2: string_vec;
        global arr3: string_vec;
        global version_arr: string_vec;

      }

    event HTTP::log_http(rec: HTTP::Info) &priority=5
        {

        if ( rec?$host && rec?$user_agent && /Macintosh; Intel Mac OS X/ in rec$user_agent && !rec?$proxied )
            {
                    arr1 = split_string1(rec$user_agent,/\(Macintosh; Intel /);

                    arr2 = split_string1(arr1[1],/\)|\;/);

                    arr3 = split_string(arr2[0], /\ /);

                 if (|arr3| > 3)
                  { version_arr = split_string(arr3[3],/\_|\./);

                    local minorVer: count;
                    local addtionalInfo: string;
                    local result: Software::name_and_version;
                    result$name = "Macintosh";


                        if(|version_arr|>=1)
                        {
                            result$version$major = to_count(version_arr[0]);

                                        if(|version_arr|>=2)
                                        {
                                           switch version_arr[1]
                                             {
                                                case "0":
                                                     minorVer=0;
                                                     addtionalInfo= "Cheetah";
                                                     break;
                                                case "1":
                                                     minorVer=1;
                                                     addtionalInfo= "Puma";
                                                     break;
                                                case "2":
                                                     minorVer=2;
                                                     addtionalInfo= "Jaguar";
                                                     break;
                                                case "3":
                                                     minorVer=3;
                                                     addtionalInfo= "Panther";
                                                     break;
                                                case "4":
                                                     minorVer=4;
                                                     addtionalInfo= "Tiger";
                                                     break;
                                                case "5":
                                                     minorVer=5;
                                                     addtionalInfo= "Leopard";
                                                     break;
                                                case "6":
                                                     minorVer=6;
                                                     addtionalInfo= "Snow Leopard";
                                                     break;
                                                case "7":
                                                     minorVer=7;
                                                     addtionalInfo= "Lion";
                                                     break;
                                                case "8":
                                                     minorVer=8;
                                                     addtionalInfo= "Mountain Lion";
                                                     break;
                                                case "9":
                                                     minorVer=9;
                                                     addtionalInfo= "Mavericks";
                                                     break;
                                                case "10":
                                                     minorVer=10;
                                                     addtionalInfo= "Yosemite";
                                                     break;
                                                case "11":
                                                     minorVer=11;
                                                     addtionalInfo= "EI Captain";
                                                     break;
                                                case "12":
                                                     minorVer=12;
                                                     addtionalInfo= "Sierra";
                                                     break;
                                                case "13":
                                                     minorVer=13;
                                                     addtionalInfo= "High Sierra";
                                                     break;
                                                case "14":
                                                     minorVer=14;
                                                     addtionalInfo= "Version later than 13";
                                                     break;
                                                default:
                                                     minorVer=0;
                                                     addtionalInfo= "UNKOWN VERSION";
                                                     break;
                                             }
                                             result$version$minor = minorVer;
                                             result$version$addl = addtionalInfo;

                                             if(|version_arr|>=3)
                                             {
                                                result$version$minor2 = to_count(version_arr[2]);
                                             }

                                        }
                                }

                        #print result;
                        Software::found(rec$id, [$version=result$version, $name=result$name, $host=rec$id$orig_h, $software_type=MACINTOSH,$unparsed_version=rec$user_agent]);
                   }
               }

#            else
#               {    if( rec?$user_agent && /\ / in rec$user_agent){
#
#                     Software::found(rec$id, [$unparsed_version=rec$user_agent, $host=rec$id$orig_h, $software_type=MACINTOSH]);
#                     }

#                    else{
#                     Software::found(rec$id, [$unparsed_version="UNKNOWN USER-AGENT", $host=rec$id$orig_h, $software_type=MACINTOSH]);
#                     }

#               }

        }
