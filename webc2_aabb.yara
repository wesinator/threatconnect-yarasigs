rule WebC2_AABB
{
meta:
    author = "Cyber Squared Inc"
    description = "Detection for new modified variant of WEBC2-QBP Comment Crew/APT1 binary. Also detects original WEBC2-QBP."
    //in_the_wild = true

    source = "https://threatconnect.com/rising-from-the-ashes-the-return-of-the-crew/"
strings:
    $aabb = "AABB//"
    $qbp = "QBP//"
    $strcmd = "dmd /c"
condition:
    ($aabb and $strcmd) or ($qbp and $strcmd)
}
