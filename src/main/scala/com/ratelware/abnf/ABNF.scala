package com.ratelware.abnf

import javax.lang.model.util.Elements

import scala.util.parsing.combinator.RegexParsers
import scala.language.postfixOps

object ABNF extends ABNFCore {

  case class RuleList(rules: List[Rule], comments: List[List[Option[Comment]]])
  def rulelist: Parser[RuleList] = rep1(rule ~ ((cwsp *) ~ cnl)) ^^ {
    rules => RuleList(rules.map(_._1), rules.map(r => r._2._1 ++ List(r._2._2)))
  }

  case class Rule(name: RuleName, definedAs: DefinedAs, elements: Elements, comment: Option[Comment])
  def rule: Parser[Rule] = (rulename ~ defined_as ~ elements ~ cnl) ^^ {
    case name ~ definedAs ~ elements ~ comment => Rule(name, definedAs, elements, comment)
  }

  case class RuleName(name: String) extends Element
  def rulename: Parser[RuleName] = alpha ~ rep(alpha | digit | "-") ^^ {
    case ALPHA(a) ~ b => RuleName(List(a) ++ b.map{
      case ALPHA(c) => c
      case DIGIT(c) => c
      case "-" => "-"
    } mkString)
  }

  case class DefinedAs(precomments: List[Comment], postcomments: List[Comment], isIncremental: Boolean)
  def defined_as: Parser[DefinedAs] = (cwsp*) ~ ("=" | "=/") ~ (cwsp*) ^^ {
    case pre ~ t ~ post => DefinedAs(pre.filter(_.isDefined).map(_.get), post.filter(_.isDefined).map(_.get), t == "=/")
  }

  case class Elements(alternation: Alternation, comments: List[Comment])
  def elements: Parser[Elements] = (alternation ~ (cwsp*)) ^^ {
    case a ~ comments => Elements(a, comments.flatMap(_.toList))
  }

  def cwsp: Parser[Option[Comment]] = (WSP | (cnl ~ WSP)) ^^ {
    case (comment: Option[Comment]) ~ _ => comment
    case _ => None
  }

  def cnl: Parser[Option[Comment]] = (comment | CRLF) ^^ {
    case a@Comment(c) => Some(a)
    case _ => None
  }

  case class Comment(c: String)
  def comment: Parser[Comment] = ";" ~ ((WSP | VCHAR)*) ~ CRLF ^^ {
    case _ ~ l ~ _ => Comment(l.mkString)
  }

  case class Alternation(path: List[Concatenation], precomments: List[List[Option[Comment]]], postcomments: List[List[Option[Comment]]])
  def alternation: Parser[Alternation] = (concatenation ~ (((cwsp*) ~ "/" ~ (cwsp*) ~ concatenation)*)) ^^ {
    case c ~ l => Alternation(List(c) ++ l.map(_._2), l.map(_._1._1._1), l.map(_._1._2))
  }

  case class Concatenation(pieces: List[Repetition], comments: List[List[Option[Comment]]])
  def concatenation: Parser[Concatenation] = (repetition ~ ((rep1(cwsp) ~ repetition)*)) ^^ {
    case r ~ reps => Concatenation(List(r) ++ reps.map(_._2), reps.map(_._1))

  }

  case class Repetition(r: Option[Repeat], elem: Element)
  def repetition: Parser[Repetition] = ((repeat?) ~ element) ^^ {
    case r ~ elem => Repetition(r, elem)
  }

  case class Repeat(min: Option[NumberVal[DIGIT]], max: Option[NumberVal[DIGIT]])
  def repeat: Parser[Repeat] = (number(digit) | ((number(digit)?) ~ "*" ~ (number(digit)?))) ^^ {
    case a: NumberVal[DIGIT] => Repeat(Some(a), Some(a))
    case (min: Option[NumberVal[DIGIT]]) ~ _ ~ (max: Option[NumberVal[DIGIT]]) => Repeat(min, max)
  }

  sealed trait Element
  def element: Parser[Element] = rulename | group | option | char_val | num_val | prose_val

  case class Group(alternation: Alternation) extends Element
  def group: Parser[Group] = ("(" ~ (cwsp*) ~ alternation ~ (cwsp*) ~ ")") ^^ {
    case _ ~_ ~ alt ~ _ ~ _ => Group(alt)
  }

  case class Opt(alternation: Alternation) extends Element
  def option: Parser[Opt] = "[" ~ (cwsp*) ~ alternation ~ (cwsp*) ~ "]" ^^ {
    case _ ~ _ ~ alt ~ _ ~ _ => Opt(alt)
  }

  case class CharVal(c: List[String]) extends Element
  def char_val: Parser[CharVal] = DQUOTE ~ (("[\u0020-\u0021]".r | "[\u0023-\u007E]".r)*) ~ DQUOTE ^^ {
    case _ ~ s ~ _ => CharVal(s)
  }

  case class NumberVal[T](d: List[T]) extends Element
  def number[T](of: Parser[T]): Parser[NumberVal[T]] = rep1(of) ^^ (l => NumberVal(l))

  case class Range[T](start: NumberVal[T], end: NumberVal[T])
  def range[T](of: Parser[T]): Parser[Range[T]] = number(of) ~ (("-" ~ number(of))?) ^^ {
    case s ~ None => Range(s, s)
    case s ~ Some(_ ~ e) => Range(s, e)
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

  case class ProseVal(value: List[String]) extends Element
  def prose_val: Parser[ProseVal] = "<" ~ (("[\u0020-\u003D]".r | "[\u003F-\u007E]".r)*) ~ ">" ^^ { case _ ~ x ~ _ => ProseVal(x) }
}
