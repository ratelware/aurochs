package com.ratelware.abnf
import scala.util.parsing.combinator._

// rules according to Appendix B of RFC5234
trait ABNFCore extends RegexParsers {
  override def skipWhitespace: Boolean = false

  case class ALPHA(c: String)
  def alpha: Parser[ALPHA] = "[a-zA-Z]".r ^^ (s => ALPHA(s))

  case class BIT(b: String)
  def bit: Parser[BIT] = ("0" | "1") ^^ (s => BIT(s))

  def CR = "\u000D"
  def LF = "\u000A"
  def CRLF = CR ~ LF

  def LOW_CTL = "[\u001F-\u007F]".r
  def HIGH_CTL = "\u007F"
  def CTL = LOW_CTL | HIGH_CTL

  case class DIGIT(d: String)
  def digit: Parser[DIGIT] = "[0-9]".r ^^ (d => DIGIT(d))
  def DQUOTE = "\""

  case class HEXDIG(h: String)
  def hexdig: Parser[HEXDIG] = (digit | "[a-fA-F]".r) ^^ {
    case DIGIT(d) => HEXDIG(d)
    case h: String => HEXDIG(h)
  }

  def HTAB = "\u0009"
  def SP = "\u0020"
  def WSP = SP | HTAB
  def LWSP = (WSP | (CRLF ~ WSP))*

  def VCHAR = "[\u0021-\u007E]".r
  def OCTET = "[\u0000-\u00FF]".r
}