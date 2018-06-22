/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_CPPMAGIC_H
#define CCAN_CPPMAGIC_H

/**
 * CPPMAGIC_NOTHING - expands to nothing
 */
#define CPPMAGIC_NOTHING()

/**
 * CPPMAGIC_STRINGIFY - convert arguments to a string literal
 */
#define _CPPMAGIC_STRINGIFY(...)	#__VA_ARGS__
#define CPPMAGIC_STRINGIFY(...)		_CPPMAGIC_STRINGIFY(__VA_ARGS__)

/**
 * CPPMAGIC_GLUE2 - glue arguments together
 *
 * CPPMAGIC_GLUE2(@a_, @b_)
 *	expands to the expansion of @a_ followed immediately
 *	(combining tokens) by the expansion of @b_
 */
#define _CPPMAGIC_GLUE2(a_, b_)		a_##b_
#define CPPMAGIC_GLUE2(a_, b_)		_CPPMAGIC_GLUE2(a_, b_)

/**
 * CPPMAGIC_1ST - return 1st argument
 *
 * CPPMAGIC_1ST(@a_, ...)
 *	expands to the expansion of @a_
 */
#define CPPMAGIC_1ST(a_, ...)		a_

/**
 * CPPMAGIC_2ND - return 2nd argument
 *
 * CPPMAGIC_2ST(@a_, @b_, ...)
 *	expands to the expansion of @b_
 */
#define CPPMAGIC_2ND(a_, b_, ...)	b_

/**
 * CPPMAGIC_ISZERO - is argument '0'
 *
 * CPPMAGIC_ISZERO(@a)
 *	expands to '1' if @a is '0', otherwise expands to '0'.
 */
#define _CPPMAGIC_ISPROBE(...)		CPPMAGIC_2ND(__VA_ARGS__, 0)
#define _CPPMAGIC_PROBE()		$, 1
#define _CPPMAGIC_ISZERO_0		_CPPMAGIC_PROBE()
#define CPPMAGIC_ISZERO(a_)		\
	_CPPMAGIC_ISPROBE(CPPMAGIC_GLUE2(_CPPMAGIC_ISZERO_, a_))

/**
 * CPPMAGIC_NONZERO - is argument not '0'
 *
 * CPPMAGIC_NONZERO(@a)
 *	expands to '0' if @a is '0', otherwise expands to '1'.
 */
#define CPPMAGIC_NONZERO(a_)		CPPMAGIC_ISZERO(CPPMAGIC_ISZERO(a_))

/**
 * CPPMAGIC_NONEMPTY - does the macro have any arguments?
 *
 * CPPMAGIC_NONEMPTY()
 * 	expands to '0'
 * CPPMAGIC_NONEMPTY(@a)
 * CPPMAGIC_NONEMPTY(@a, ...)
 * 	expand to '1'
 */
#define CHECK_N(x, n, ...) n
#define CHECK(...) CHECK_N(__VA_ARGS__, , )
#define PROBE(x) x, 1,
#define IS_PAREN(x, ...) CHECK(IS_PAREN_PROBE x)
#define IS_PAREN_PROBE(...) PROBE(~)

#define _CPPMAGIC_EOA(a_, ...)			0
#define CPPMAGIC_NONEMPTY(...)		\
	CPPMAGIC_NONZERO(CPPMAGIC_1ST(_CPPMAGIC_EOA IS_PAREN(__VA_ARGS__) __VA_ARGS__)())

/**
 * CPPMAGIC_ISEMPTY - does the macro have no arguments?
 *
 * CPPMAGIC_ISEMPTY()
 * 	expands to '1'
 * CPPMAGIC_ISEMPTY(@a)
 * CPPMAGIC_ISEMPTY(@a, ...)
 * 	expand to '0'
 */
#define CPPMAGIC_ISEMPTY(...)		\
	CPPMAGIC_ISZERO(CPPMAGIC_NONEMPTY(__VA_ARGS__))

/*
 * CPPMAGIC_IFELSE - preprocessor conditional
 *
 * CPPMAGIC_IFELSE(@cond)(@if)(@else)
 *	expands to @else if @cond is '0', otherwise expands to @if
 */
#define _CPPMAGIC_IF_0(...)		_CPPMAGIC_IF_0_ELSE
#define _CPPMAGIC_IF_1(...)		__VA_ARGS__ _CPPMAGIC_IF_1_ELSE
#define _CPPMAGIC_IF_0_ELSE(...)	__VA_ARGS__
#define _CPPMAGIC_IF_1_ELSE(...)
#define _CPPMAGIC_IFELSE(cond_)		CPPMAGIC_GLUE2(_CPPMAGIC_IF_, cond_)
#define CPPMAGIC_IFELSE(cond_)		\
	_CPPMAGIC_IFELSE(CPPMAGIC_NONZERO(cond_))

/**
 * CPPMAGIC_EVAL - force multiple expansion passes
 *
 * Forces macros in the arguments to be expanded repeatedly (up to
 * 1024 times) even when CPP would usually stop expanding.
 */
#define CPPMAGIC_EVAL1(...)		__VA_ARGS__
#define CPPMAGIC_EVAL2(...)		\
	CPPMAGIC_EVAL1(CPPMAGIC_EVAL1(__VA_ARGS__))
#define CPPMAGIC_EVAL4(...)		\
	CPPMAGIC_EVAL2(CPPMAGIC_EVAL2(__VA_ARGS__))
#define CPPMAGIC_EVAL8(...)		\
	CPPMAGIC_EVAL4(CPPMAGIC_EVAL4(__VA_ARGS__))
#define CPPMAGIC_EVAL16(...)		\
	CPPMAGIC_EVAL8(CPPMAGIC_EVAL8(__VA_ARGS__))
#define CPPMAGIC_EVAL32(...)		\
	CPPMAGIC_EVAL16(CPPMAGIC_EVAL16(__VA_ARGS__))
#define CPPMAGIC_EVAL64(...)		\
	CPPMAGIC_EVAL32(CPPMAGIC_EVAL32(__VA_ARGS__))
#define CPPMAGIC_EVAL128(...)		\
	CPPMAGIC_EVAL64(CPPMAGIC_EVAL64(__VA_ARGS__))
#define CPPMAGIC_EVAL256(...)		\
	CPPMAGIC_EVAL128(CPPMAGIC_EVAL128(__VA_ARGS__))
#define CPPMAGIC_EVAL512(...)		\
	CPPMAGIC_EVAL256(CPPMAGIC_EVAL256(__VA_ARGS__))
#define CPPMAGIC_EVAL1024(...)		\
	CPPMAGIC_EVAL512(CPPMAGIC_EVAL512(__VA_ARGS__))
#define CPPMAGIC_EVAL(...)		CPPMAGIC_EVAL1024(__VA_ARGS__)

/**
 * CPPMAGIC_DEFER1, CPPMAGIC_DEFER2 - defer expansion
 */
#define CPPMAGIC_DEFER1(a_)	a_ CPPMAGIC_NOTHING()
#define CPPMAGIC_DEFER2(a_)	a_ CPPMAGIC_NOTHING CPPMAGIC_NOTHING()()

/**
 * CPPMAGIC_MAP - iterate another macro across arguments
 * @m: name of a one argument macro
 *
 * CPPMAGIC_MAP(@m, @a1, @a2, ... @an)
 *	expands to the expansion of @m(@a1) , @m(@a2) , ... , @m(@an)
 */
#define _CPPMAGIC_MAP_()		_CPPMAGIC_MAP
#define _CPPMAGIC_MAP(m_, a_, ...)					\
	m_(a_)								\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(, CPPMAGIC_DEFER2(_CPPMAGIC_MAP_)()(m_, __VA_ARGS__))	\
		()
#define CPPMAGIC_MAP(m_, ...)						\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(CPPMAGIC_EVAL(_CPPMAGIC_MAP(m_, __VA_ARGS__)))		\
		()

/**
 * CPPMAGIC_2MAP - iterate another macro across pairs of arguments
 * @m: name of a two argument macro
 *
 * CPPMAGIC_2MAP(@m, @a1, @b1, @a2, @b2, ..., @an, @bn)
 *	expands to the expansion of
 *		 @m(@a1, @b1) , @m(@a2, @b2) , ... , @m(@an, @bn)
 */
#define _CPPMAGIC_2MAP_()		_CPPMAGIC_2MAP
#define _CPPMAGIC_2MAP(m_, a_, b_, ...)				\
	m_(a_, b_)							\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(, CPPMAGIC_DEFER2(_CPPMAGIC_2MAP_)()(m_, __VA_ARGS__)) \
		()
#define CPPMAGIC_2MAP(m_, ...)					\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(CPPMAGIC_EVAL(_CPPMAGIC_2MAP(m_, __VA_ARGS__)))	\
		()

/**
 * CPPMAGIC_MAP_CNT - iterate antoher macro across arguments adding a count
 * @m: name of a two argument macro
 *
 * CPPMAGIC_MAP_CNT(@m, @a1, @a2, ..., @an)
 *      expands to the expansion of
 *            @m(0, @a1) , @m(1, @a2) , ... , @m(n - 1, @an)
 */
#define _CPPMAGIC_MAP_CNT_()		_CPPMAGIC_MAP_CNT
#define _CPPMAGIC_MAP_CNT(m_, c_, a_, ...)				\
	m_(c_, a_)							\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
	(, CPPMAGIC_DEFER2(_CPPMAGIC_MAP_CNT_)()(m_, CPPMAGIC_INC(c_), __VA_ARGS__)) \
	()
#define CPPMAGIC_MAP_CNT(m_, ...)				\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))		\
	(CPPMAGIC_EVAL(_CPPMAGIC_MAP_CNT(m_, 0, __VA_ARGS__)))	\
	()

/**
 * CPPMAGIC_JOIN - separate arguments with given delimiter
 * @d: delimiter
 *
 * CPPMAGIC_JOIN(@d, @a1, @a2, ..., @an)
 *	expands to the expansion of @a1 @d @a2 @d ... @d @an
 */
#define _CPPMAGIC_JOIN_()		_CPPMAGIC_JOIN
#define _CPPMAGIC_JOIN(d_, a_, ...)					\
	a_								\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(d_ CPPMAGIC_DEFER2(_CPPMAGIC_JOIN_)()(d_, __VA_ARGS__)) \
		()
#define CPPMAGIC_JOIN(d_, ...)					\
	CPPMAGIC_IFELSE(CPPMAGIC_NONEMPTY(__VA_ARGS__))			\
		(CPPMAGIC_EVAL(_CPPMAGIC_JOIN(d_, __VA_ARGS__)))	\
		()

/**
 * CPPMAGIC_INC - increment the argument
 * @d: integer between 0 and 32 to increment
 *
 * Increments the integer to a maximum of 32 and saturates
 */
#define CPPMAGIC_INC(d_) CPPMAGIC_GLUE2(_CPPMAGIC_INC_, d_)
#define _CPPMAGIC_INC_0 1
#define _CPPMAGIC_INC_1 2
#define _CPPMAGIC_INC_2 3
#define _CPPMAGIC_INC_3 4
#define _CPPMAGIC_INC_4 5
#define _CPPMAGIC_INC_5 6
#define _CPPMAGIC_INC_6 7
#define _CPPMAGIC_INC_7 8
#define _CPPMAGIC_INC_8 9
#define _CPPMAGIC_INC_9 10
#define _CPPMAGIC_INC_10 11
#define _CPPMAGIC_INC_11 12
#define _CPPMAGIC_INC_12 13
#define _CPPMAGIC_INC_13 14
#define _CPPMAGIC_INC_14 15
#define _CPPMAGIC_INC_15 16
#define _CPPMAGIC_INC_16 17
#define _CPPMAGIC_INC_17 18
#define _CPPMAGIC_INC_18 19
#define _CPPMAGIC_INC_19 20
#define _CPPMAGIC_INC_20 21
#define _CPPMAGIC_INC_21 22
#define _CPPMAGIC_INC_22 23
#define _CPPMAGIC_INC_23 24
#define _CPPMAGIC_INC_24 25
#define _CPPMAGIC_INC_25 26
#define _CPPMAGIC_INC_26 27
#define _CPPMAGIC_INC_27 28
#define _CPPMAGIC_INC_28 29
#define _CPPMAGIC_INC_29 30
#define _CPPMAGIC_INC_30 31
#define _CPPMAGIC_INC_31 32
#define _CPPMAGIC_INC_32 32

#endif /* CCAN_CPPMAGIC_H */
