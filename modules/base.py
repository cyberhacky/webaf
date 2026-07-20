from abc import ABC, abstractmethod


class AssessmentPlugin(ABC):

    name = "Base"

    @abstractmethod
    def run(self, client, inventory):
        """
        Execute the assessment.

        Returns:
            list[dict]
        """
        raise NotImplementedError
