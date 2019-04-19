#Written by boran@arksoft.com.tr on 4/19/2019
#Lists exchange users' IP location based on IIS logs
#Turkey's IP ranges and country IP database are taken from IP2Location.com. They are LITE and free versions and may not accurate
#Aim of this script is to give an idea about querying users' location against any credantial theft of users. 
#Please use your own IP databases
#Input csv file needs to be created before via logparser query. In this example, x-forwarded-for field keeps the original client IP. Use the correct field for original client IP, use c-ip field if there is LB in environment.

$UsersIP=Import-Csv .\IP-OWA.csv #Users' IP addresses, taken from IIS Logs via Logparser "select distinct cs-username, x-forwarded-for From \\w3svc1logpat where cs-username IS NOT NULL to IP-owa.csv" -i:w3c o:csv"

function Convert-IPv4 {
       param   
    (   
        [Parameter(Mandatory = $true)]   
        [ValidateScript({$_ -match [IPAddress]$_ })]
              [Alias("IP")]
        [String] $IPv4Addr,
              
              [Parameter(Mandatory = $false)]
              [ValidateSet('Binary','Decimal')]
              [String] $To = 'Binary'
    )
       
       $IPv4 = [IPAddress] $IPv4Addr
    
        if ($To -eq 'Binary')
       {
       foreach ($Decimal in $IPv4.GetAddressBytes())
              {
                     $Byte = [Convert]::ToString($Decimal,2)
              
                     if ($Byte.Length -lt 8)
                     {
                           for ($i = $Byte.Length; $i -lt 8; $i++)
                           {
                                         $Byte = "0$Byte"
                           }
                     }
              
                     $IPv4_Binary = $IPv4_Binary + $Byte
              }
       
              return $IPv4_Binary
       }
       
       else
       {
              $IPv4_Decimal = 0
       
              $Byte_Position = 4
              
              foreach ($Decimal in $IPv4.GetAddressBytes())
              {
                     $Byte_Position--
                     
                     $Byte = [Convert]::ToString($Decimal,2)
                     
                     $Bit_Index = $null
                     
                     foreach ($Bit in $Byte.ToCharArray())
                     {
                           $Bit_Index++
                           
                           $IPv4_Decimal = $IPv4_Decimal + ( [Int]$Bit.ToString() * [Math]::Pow( 2, ( $Byte.Length - $Bit_Index + (8*$Byte_Position) ) ) )
                     }
              }
              
              return $IPv4_Decimal
       }
}

#region IP ranges
$PrivIPRange=@() #Array for Private IP ranges
$PrivIPRange+=@{Low= Convert-IPv4 '10.0.0.0' -To Decimal;High=Convert-IPv4 '10.255.255.255' -To Decimal}
$PrivIPRange+=@{Low= Convert-IPv4 '172.16.0.0' -To Decimal;High=Convert-IPv4 '172.31.255.255' -To Decimal}
$PrivIPRange+=@{Low= Convert-IPv4 '192.168.0.0' -To Decimal;High=Convert-IPv4 '192.168.255.255' -To Decimal}
[Collections.Generic.List[Object]]$IPPrivList=$PrivIPRange |  % { new-object PSObject -Property $_}


# Country IP databases
$UsersIP=Import-Csv .\Desktop\IPKarsilastir\IP-OWA.csv -Delimiter ";" #Users IP addresses, taken from IIS Logs via Logparser like "select distinct cs-username, x-forwarded-for From \\w3svc1logpat where cs-username IS NOT NULL to IP-owa.csv" -i:w3c o:csv"
$TrIPdb = [Collections.Generic.List[Object]](Import-csv .\turkeyIPrange-dec.csv)
$IPdb = [Collections.Generic.List[Object]](Import-csv .\IP2LOCATION-LITE-DB1.csv)
#endregion 

$foreingUsers=@()

Foreach ($IP in $UsersIP) {

IF($IP.'x-forwarded-for') {

$cvedIP=Convert-IPv4 -IPv4Addr $IP.'x-forwarded-for' -To Decimal
$IndexPr=$IPPrivList.FindIndex( {$args[0].Low -lt $cvedIP -and $args[0].High -gt $cvedIP} ) 

If($IndexPr -eq "-1") {
    Write-host $IP.'cs-username :' `t -NoNewline
    $index = $TrIPdb.FindIndex( {$args[0].LDec -lt $cvedIP -and $args[0].HDec -gt $cvedIP} )
    If($index -ne "-1") {
     Write-host $IP.'cs-username' `t $IP.'x-forwarded-for' `t " Ulkede" -ForegroundColor DarkMagenta -BackgroundColor Yellow
    }
    Else {

    
    $IndexY=$IPdb.FindIndex( {$args[0].LDec -lt $cvedIP -and $args[0].HDec -gt $cvedIP} )

    $IP |Add-Member -Name Country -Value $IPdb[$IndexY].country -MemberType NoteProperty
    $foreingUsers+=$IP
    
    Write-host $IP.'cs-username' `t $IP.'x-forwarded-for' `t $IPdb[$IndexY].country -ForegroundColor White -BackgroundColor Red
    }
}
}



}

$foreingUsers | Export-Csv .\yurtdisikullanicilar.csv -NoTypeInformation


