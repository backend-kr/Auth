from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 1000

    def get_paginated_response(self, data):
        try:
            current = int(self.request.GET.get('page'))
        except TypeError:
            current = 1

        try:
            p_size = int(self.request.GET.get(self.page_size_query_param))
        except TypeError:
            p_size = self.page_size

        result = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'page_count': self.page.paginator.num_pages,
            'page_current': current,
            'page_size': p_size,
            'data': data
        }

        return Response(data=result)
