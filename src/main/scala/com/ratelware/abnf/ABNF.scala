package com.ratelware.abnf

import scala.util.parsing.combinator.RegexParsers

object ABNF extends ABNFCore {
  def rulelist = rep1(rule | ((cwsp*) ~ cnl))
  def rule = rulename ~ defined_as ~ elements ~ cnl

  case class RuleName(name: String)
  def rulename = alpha ~ rep(alpha | digit | "-") ^^ {
    case ALPHA(a) ~ b => b.map{
      case ALPHA(c) => c
      case DIGIT(c) => c
      case "-" => "-"
    } +: a mkString
  }

  case class DefinedAs(precomments: List[Comment], postcomments: List[Comment], isIncremental: Boolean)
  def defined_as = (cwsp*) ~ ("=" | "=/") ~ (cwsp*) ^^ {
    case pre ~ t ~ post => DefinedAs(pre.filter(_.isDefined).map(_.get), post.filter(_.isDefined).map(_.get), t == "=/")
  }

  def elements = alternation ~ (cwsp*)

  def cwsp: Parser[Option[Comment]] = (WSP | (cnl ~ WSP)) ^^ {
    case c ~ _ => c
    case _ => None
  }

  def cnl: Parser[Option[Comment]] = (comment | CRLF) ^^ {
    case a@Comment(c) => Some(a)
    case (_, _) => None
  }

  case class Comment(c: String)
  def comment: Parser[Comment] = ";" ~ ((WSP | VCHAR)*) ~ CRLF ^^ {
    case _ ~ l ~ _ => Comment(l.mkString)
  }

  def alternation = concatenation ~ (((cwsp*) ~ "/" ~ (cwsp*) ~ concatenation)*)
  def concatenation = repetition ~ ((rep1(cwsp) ~ repetition)*)
  def repetition = (repeat?) ~ element

  case class Repeat(min: Option[NumberVal[DIGIT]], max: Option[NumberVal[DIGIT]])
  def repeat = (number(digit) | ((number(digit)?) ~ "*" ~ (number(digit)?))) ^^ {
    case a: NumberVal[DIGIT] => Repeat(Some(a), Some(a))
    case (min: NumberVal[DIGIT]) ~ _ ~ (max: NumberVal[DIGIT]) => Repeat(Some(min), Some(max))
  }

  sealed trait Element
  def element = rulename | group | option | char_val | num_val | prose_val
  def group = "(" ~ (cwsp*) ~ alternation ~ (cwsp*) ~ ")"
  def option = "[" ~ (cwsp*) ~ alternation ~ (cwsp*) ~ "]"

  def CharVal(c: List[String])
  def char_val = DQUOTE ~ (("[\u0020-\u0021]".r | "[\u0023-\u007E]".r)*) ~ DQUOTE ^^ {
    case _ ~ s ~ _ => CharVal(s)
  }

  case class NumberVal[T](d: List[T])
  def number[T](of: Parser[T]): Parser[NumberVal[T]] = rep1(of) ^^ (l => NumberVal(l))

  case class Range[T](start: NumberVal[T], end: Option[NumberVal[T]])
  def range[T](of: Parser[T]): Parser[Range[T]] = number(of) ~ (("-" ~ number(of))?) ^^ {
    case s ~ None => Range(s, None)
    case s ~ Some(_ ~ e) => Range(s, Some(e))
  }

  case class ConcatenatedRanges[T](ranges: List[Range[T]])
  def ranges[T](of: Parser[T]): Parser[ConcatenatedRanges[T]] = range(of) ~ rep("." ~ range(of)) ^^ {
    case s ~ t => ConcatenatedRanges(List(s) ++ t.map(_._2))
  }

  sealed trait NumVal extends Element
  def num_val = "%" ~ (bin_val | dec_val | hex_val) ^^ { case _ ~ a => a }

  case class BinVal(r: ConcatenatedRanges[BIT]) extends NumVal
  def bin_val = "b" ~ ranges(bit) ^^ { case _ ~ r => BinVal(r)}
  case class DecVal(r: ConcatenatedRanges[DIGIT]) extends NumVal
  def dec_val = "d" ~ ranges(digit) ^^ { case _ ~ d => DecVal(d) }
  case class HexVal(r: ConcatenatedRanges[HEXDIG]) extends NumVal
  def hex_val = "x" ~ ranges(hexdig) ^^ { case _ ~ h => HexVal(h) }

  case class ProseVal(value: List[String])
  def prose_val = "<" ~ (("[\u0020-\u003D]".r | "[\u003F-\u007E]".r)*) ~ ">" ^^ { case _ ~ x ~ _ => ProseVal(x) }
}
