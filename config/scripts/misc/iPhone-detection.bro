# Script to determine iOS version.
# Fatemabw, 2016

@load base/protocols/http
@load base/frameworks/software

module iOS;

    export {
        redef enum Software::Type += {
        ## Identifier for Mac operating system versions
             IPHONE,
        };

        type Software::name_and_version: record {
                name   : string;
                version: Software::Version;
        };

      }

    event HTTP::log_http(rec: HTTP::Info) &priority=5
        {

        if ( rec?$host && rec?$user_agent && /iPhone; CPU iPhone OS/ in rec$user_agent && !rec?$proxied )
            {
                    local arr1: string_vec;
                    local arr2: string_vec;
                    local result: Software::name_and_version;
                    local version_arr: string_vec;

                    arr1 = split_string1(rec$user_agent,/iPhone; CPU iPhone OS /);
                    arr2 = split_string1(arr1[1],/\ /);
                    result$name = "iPhone";

                if (|arr2| > 0)
                    { version_arr = split_string(arr2[0],/\_|\./);

                    if(|version_arr|>=1)
                        {
                            result$version$major = to_count(version_arr[0]);

                           if(|version_arr|>=2)
                            {
                                result$version$minor = to_count(version_arr[1]);
                            }

                           if(|version_arr|>=3)
                            {
                                result$version$minor2 = to_count(version_arr[2]);
                            }

                        }
                    }
                if (/FBDV\/iPhone/ in rec$user_agent)
                    {
                        local arr3: string_vec;
                        local arr4: string_vec;
                        local addtionalInfo1: string;

                        arr3 = split_string1(rec$user_agent, /FBDV\//);
                        arr4 = split_string1(arr3[1], /\;/);
                        addtionalInfo1 = arr4[0];
                        result$version$addl = addtionalInfo1;

                        if (/FBCR\// in rec$user_agent)
                        {
                            local arr5: string_vec;
                            local arr6: string_vec;
                            local addtionalInfo2: string;

                            arr5 = split_string1(rec$user_agent, /FBCR\//);
                            arr6 = split_string1(arr5[1], /\;/);
                            addtionalInfo2 = arr6[0];
                            result$version$addl = string_cat(result$version$addl,addtionalInfo2);
                        }

                    }
                if (result?$version)
                    {
                        Software::found(rec$id, [$version=result$version, $name=result$name, $host=rec$id$orig_h, $software_type=IPHONE,$unparsed_version=rec$user_agent]);
                    }
                else
                    {
                        Software::found(rec$id, [$unparsed_version=sub(rec$user_agent,/iPhone; CPU iPhone OS/, "Unknown CryptoAPI Version"), $host=rec$id$orig_h, $software_type=IPHONE]);
                    }
           }
        }

