using AutoMapper;
using SecureApiWithJwt.Models;

namespace SecureApiWithJwt.Helpers
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, UserInfoDto>()
                .ForMember(dest => dest.UserId, act => act.MapFrom(src => src.Id));
        }
    }
}
