function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 14, 14)
    val_2 <- substr(flag, 18, 18)
    val_3 <- substr(flag, 24, 24)
    val_4 <- substr(flag, 32, 32)
    val_5 <- substr(flag, 36, 36)
    val_6 <- substr(flag, 62, 62)
    (val_1 == val_2) & (val_1 == "a") & (val_1 == val_3) & (val_3 == 
        val_4) & (val_5 == val_4) & (val_6 == val_5)
}
<bytecode: 0x557183cd0b48>
Errore in readRDS("127") : nessun metodo di ripristino disponibile
> readRDS("1561")
readRDS("16DA")
readRDS("198D")
readRDS("1BF5")
readRDS("1EFA")
readRDS("20F9")
readRDS("253")
readRDS("2535")
readRDS("273F")
readRDS("287")
readRDS("2A27")
readRDS("2CC1")
readRDS("2E40")
readRDS("2FBE")
readRDS("309")
readRDS("3148")
readRDS("332A")
readRDS("33D")
readRDS("35BD")
readRDS("373")
readRDS("37F5")
readRDS("4")
readRDS("86")
readRDS("D37")
readRDS("FF3")
function (index, val) 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, index, index)
    val_1 == val
}
<bytecode: 0x557183cf4888>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 72, 72)
    val_2 <- substr(flag, 92, 92)
    val_3 <- substr(flag, 26, 26)
    val_4 <- substr(flag, 34, 34)
    val_5 <- substr(flag, 60, 60)
    (val_1 == val_2) & (val_1 == val_3) & (val_1 == val_4) & 
        (val_1 == val_5)
}
<bytecode: 0x557183d07ac8>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 22, 22)
    val_2 <- substr(flag, 48, 48)
    val_3 <- substr(flag, 78, 78)
    val_4 <- substr(flag, 89, 89)
    (val_1 == val_2) & (val_1 == val_3) & (val_1 == val_4)
}
<bytecode: 0x557183d1de78>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 51, 51)
    val_2 <- substr(flag, 59, 59)
    val_3 <- substr(flag, 63, 63)
    val_4 <- substr(flag, 65, 65)
    val_5 <- substr(flag, 77, 77)
    val_6 <- substr(flag, 91, 91)
    (val_1 == val_2) & (val_1 == val_3) & (val_1 == val_4) & 
        (val_1 == val_5) & (val_1 == val_6)
}
<bytecode: 0x557183d36458>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- as.integer(substr(flag, 51, 51))
    val_2 <- as.integer(substr(flag, 22, 22))
    (val_1 - val_2) == 1
}
<bytecode: 0x557183d4ca78>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 17, 17)
    val_2 <- substr(flag, 23, 23)
    val_3 <- substr(flag, 28, 28)
    val_4 <- substr(flag, 35, 35)
    val_5 <- substr(flag, 37, 37)
    val_6 <- substr(flag, 43, 43)
    val_7 <- substr(flag, 44, 44)
    val_8 <- substr(flag, 52, 52)
    val_9 <- substr(flag, 69, 69)
    val_10 <- substr(flag, 74, 74)
    (val_1 == val_2) & (val_1 == val_3) & (val_1 == val_4) & 
        (val_1 == val_5) & (val_1 == val_6) & (val_1 == val_7) & 
        (val_1 == val_8) & (val_1 == val_9) & (val_1 == val_10)
}
<bytecode: 0x557183d61820>
Errore in readRDS("253") : nessun metodo di ripristino disponibile
> 
readRDS("2535")
readRDS("273F")
readRDS("287")
readRDS("2A27")
readRDS("2CC1")
readRDS("2E40")
readRDS("2FBE")
readRDS("309")
readRDS("3148")
readRDS("332A")
readRDS("33D")
readRDS("35BD")
readRDS("373")
readRDS("37F5")
readRDS("4")
readRDS("86")
readRDS("D37")
readRDS("FF3")
function () 
{
    flag <- get_flag_or_die()
    val_1 <- as.integer(substr(flag, 17, 17))
    val_2 <- as.integer(substr(flag, 87, 87))
    (val_1 - val_2) == -2
}
<bytecode: 0x557183d7ee58>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- as.integer(substr(flag, 7, 8))
    val_2 <- as.integer(substr(flag, 9, 10))
    val_3 <- as.integer(substr(flag, 89, 91))
    val_4 <- as.integer(substr(flag, 92, 93))
    ((val_1 - val_2) == 9) & ((val_3 + val_4) == 680)
}
<bytecode: 0x557183d917a0>
$bindings
named list()

$enclos
<environment: base>

$attributes
NULL

$isS4
[1] FALSE

$locked
[1] FALSE

function () 
{
    flag <- get_flag_or_die()
    x <- 9
    delayedAssign("y", x)
    x <- x * (x - 5 + 4 + 6 - 3 - 2 - 3 - 6)
    as.integer(substr(flag, 1, 1)) == y
}
<bytecode: 0x557183da8dc0>
function () 
{
    flag <- get_flag_or_die()
    as.integer(substr(flag, 25, 29)) == 25213
}
<bytecode: 0x557183dc1590>
function () 
{
    flag <- get_flag_or_die()
    as.integer(substr(flag, 7, 11)) == 29202
}
<bytecode: 0x557183dd4650>
function (index_0, index_1, val) 
{
    flag <- get_flag_or_die()
    as.integer(substr(flag, index_0, index_1)) == val
}
<bytecode: 0x557183deb4f8>
Errore in readRDS("309") : nessun metodo di ripristino disponibile
> readRDS("3148")
readRDS("332A")
readRDS("33D")
readRDS("35BD")
readRDS("373")
readRDS("37F5")
readRDS("4")
readRDS("86")
readRDS("D37")
readRDS("FF3")
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 16, 16)
    val_2 <- substr(flag, 30, 30)
    (val_1 == val_2) & (val_1 == "f")
}
<bytecode: 0x557183e034b0>
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 42, 42)
    val_2 <- substr(flag, 50, 50)
    val_3 <- substr(flag, 56, 56)
    val_4 <- substr(flag, 80, 80)
    (val_1 == val_2) & (val_1 == "d") & (val_1 == val_3) & (val_3 == 
        val_4)
}
<bytecode: 0x557183e160c0>
[1] "BHMEA2024"
function () 
{
    flag <- get_flag_or_die()
    val_1 <- substr(flag, 54, 54)
    val_2 <- substr(flag, 84, 84)
    val_3 <- substr(flag, 12, 12)
    (val_1 == val_2) & (val_1 == "e") & (val_1 == val_3)
}
<bytecode: 0x557183e31260>
function (flag) 
{
    check_val_0() & check_val_1(94, 82, 6) & check_val_2() & 
        check_val_1(1, 86, 10) & check_val_3() & check_val_1(90, 
        83, 9) & check_val_1(9, 11, 15) & check_val_4() & check_val_1(29, 
        61, 57) & check_val_5() & check_val_6(67, 71, 22103) & 
        check_val_6(72, 76, 50138) & check_val_7() & check_val_8() & 
        check_val_9() & (substr(get_flag_or_die(), 6, 6) == "b") & 
        check_val_6(37, 41, 19230) & check_val_6(43, 47, 11202) & 
        check_val_10() & check_val_11(76, "8") & check_val_11(93, 
        "3") & check_val_11(13, "0") & check_val_6(77, 79, 763) & 
        check_val_6(85, 87, 303) & check_val_6(59, 61, 753) & 
        check_val_12() & check_val_11(26, "5") & check_val_13() & 
        check_val_14() & check_val_11(87, "3") & check_val_15() & 
        check_val_11(88, "c") & check_val_16() & check_val_17() & 
        check_val_11(81, "0") & check_val_11(86, "0") & check_val_11(17, 
        "1") & check_val_11(18, "a") & check_val_6(39, 41, 230) & 
        check_val_6(21, 23, 361) & check_val_11(39, "2") & check_val_11(58, 
        "2") & check_val_6(51, 53, 713) & check_val_6(33, 35, 
        351) & check_val_11(19, "2") & check_val_11(20, "b") & 
        check_val_11(31, "3") & check_val_6(45, 47, 202) & check_val_11(44, 
        "1") & check_val_11(49, "3") & check_val_11(55, "3") & 
        check_val_11(44, "1") & check_val_11(45, "2") & check_val_6(63, 
        65, 707) & check_val_11(66, "c")
}
<bytecode: 0x557183e45948>
function () 
{
    if (exists("flag", envir = .GlobalEnv)) {
        flag_value <- get("flag", envir = .GlobalEnv)
        if (is.character(flag_value)) {
            xor_key <- "BHMEAISTHEBESTCTFEVERBETTERTHANALLOFTHEOTHERCTF"
            key_length <- nchar(xor_key)
            flag_length <- nchar(flag_value)
            if (flag_length != key_length) {
                xor_key <- substr(rep(xor_key, length.out = ceiling(flag_length/key_length)), 
                  1, flag_length)
            }
            xor_result <- sapply(1:flag_length, function(i) {
                flag_char <- substr(flag_value, i, i)
                key_char <- substr(xor_key, i, i)
                int_val <- as.integer(charToRaw(flag_char))
                xor_val <- as.integer(charToRaw(key_char))
                xored_val <- bitwXor(int_val, xor_val)
                as.raw(xored_val)
            })
            return(paste0(xor_result, collapse = ""))
        }
    }
    else {
        system("echo 'try better next time'")
    }
}
<bytecode: 0x557183e63a98>
$bindings
named list()

$enclos
<environment: base>

$attributes
NULL

$isS4
[1] FALSE

$locked
[1] FALSE

$bindings
named list()

$enclos
<environment: base>

$attributes
$attributes$name
[1] "lazydata:BHMEA2024"


$isS4
[1] FALSE

$locked
[1] FALSE

function () 
{
    flag <- get_flag_or_die()
    if (nchar(flag) < 5) {
        return(FALSE)
    }
    first_five <- substr(flag, 1, 5)
    all_same <- all(strsplit(first_five, "")[[1]] == substr(flag, 
        1, 1))
    return(all_same)
}
<bytecode: 0x557183e84b80>
function (index_0, index_1, index_2) 
{
    flag <- get_flag_or_die()
    first_two <- substr(flag, index_0, index_0) == substr(flag, 
        index_1, index_1)
    second_two <- substr(flag, index_1, index_1) == substr(flag, 
        index_2, index_2)
    final <- all(first_two, second_two)
    return(final)
}
<bytecode: 0x557183e9f1c8>