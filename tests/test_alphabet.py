from miskzi_ciphers.common.alphabet import RU_33, _cached_index, build_index, shift_char


def test_shift_char_ru33():
    assert shift_char("А", alphabet=RU_33, k=3) == "Г"
    assert shift_char("Я", alphabet=RU_33, k=1) == "А"
    assert shift_char("!", alphabet=RU_33, k=5) is None


def test_alphabet_index_cache_hits_increase():
    _cached_index.cache_clear()

    first = build_index(RU_33)
    second = build_index(RU_33)

    assert first is second
    assert _cached_index.cache_info().hits > 0
