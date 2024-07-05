from model_utils import Choices


class ProfileChoices:
    MOBILE_CARRIER = Choices(
        ('01', 'skt', 'SKT'),
        ('02', 'kt', 'KT'),
        ('03', 'lg', 'LG U+'),
        ('알뜰폰', [
            ('04', 'r_skt', 'SKT'),
            ('05', 'r_kt', 'KT'),
            ('06', 'r_lg', 'LG U+')
        ]),
    )

    GENDER_TYPE = Choices(
        ('내국인', [
            (1, 'l1', '남(1)'),
            (2, 'l2', '여(2)'),
            (3, 'l3', '남(3)'),
            (4, 'l4', '여(4)'),
            (9, 'l9', '남(9)'),
            (0, 'l0', '여(10)'),
        ]),
        ('외국인', [
            (5, 'f5', '남(5)'),
            (6, 'f6', '여(6)'),
            (7, 'f7', '남(7)'),
            (8, 'f8', '여(8)'),
        ])
    )


class VendorPropertyChoices:
    TYPE = Choices(('investment', '증권사'),
                   ('partner', '협력사'),
    )


class ActivationLogChoices:
    EMAIL_CONFIRM_TYPE = (
        ('signup', 'signup'),
        ('password_reset', 'password_reset'),
        ('validate_email', 'validate_email'),
    )

    EXPIRE_CONFIRM_TYPE = (
        ('signup', '1/days'),
        ('password_reset', '1/days'),
        ('validate_email', '5/minutes'),
    )
