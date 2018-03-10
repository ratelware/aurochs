package com.ratelware.abnf

object Translator extends App {

  val grammar =
    s"""
      |CR             =  %x0D; carriage return
      |
      |CRLF           =  CR LF
      |
      |CTL            =  %x00-1F / %x7F
      |
      |DIGIT          =  %x30-39
      |
      |DQUOTE         =  %x22
      |
      |HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
      |
      |HTAB           =  %x09
      |
      |LF             =  %x0A
      |
      |LWSP           =  *(WSP / CRLF WSP)
      |
      |OCTET          =  %x00-FF
      |
      |SP             =  %x20
      |
      |VCHAR          =  %x21-7E
      |
      |WSP            =  SP / HTAB
      |
      |
    """.stripMargin.trim + "\r\n\r\n" +
      ""

  val p = ABNF.parseAll(ABNF.rulelist, grammar)
  p match {
    case ABNF.Success(t, _) => println(t)
    case a => {
      println(a)
    }
  }
}
